"""A clearly labelled direct-run cost scenario, not a token-count guarantee."""
import html
import math

from .reports import rate_for


def forecast(app, params, projection):
    if not params.get('api') and not (params.get('judge_model') and 'llm' in params.get('judges','').split(',')):
        return ''
    body = '<section class="card"><h2>Hosted cost estimate</h2>'
    if not projection:
        return body+'<p>Available after the automatic workload check.</p></section>'
    try:
        snapshot, _, _, _ = app._selected_api_config_snapshot(params)
        pricing = app._load_registry('pricing.json','rig/pricing.example.json')
        totals = projection['call_projection']
        targets = set(app._split_list(params.get('api','')))
        rows=[]; first=0.0; full=0.0; incomplete=False
        for route in snapshot['routes']:
            spec=route['requested_spec']; config=route['config']
            calls=int(totals['target_calls'] if spec in targets else totals['judge_calls'])
            if not calls:
                continue
            rate, why=rate_for(pricing,route['provider'],route['model'])
            allowance=config.get('max_tokens')
            money='Not estimated: '+why if rate is None else ''
            if rate and isinstance(allowance,int) and allowance>0:
                rates=rate.get('per_million_tokens',{})
                try:
                    ip=float(rates['input']); op=float(rates['output'])
                    if rate.get('currency')!='USD' or not all(math.isfinite(x) and x>=0 for x in (ip,op)):
                        raise ValueError('price')
                    expected=calls*(4096*ip+max(1,allowance//4)*op)/1e6
                    maximum=calls*(4096*ip+allowance*op)/1e6
                    first+=expected; full+=maximum
                    money=f'${expected:.4f} / ${maximum:.4f}'
                except (KeyError,TypeError,ValueError):
                    money='Not estimated: complete USD token prices required'
            elif rate:
                money='Not estimated: explicit output allowance required'
            incomplete |= money.startswith('Not estimated')
            cells=(spec,str(calls),str(allowance or 'not recorded'),money)
            rows.append('<tr>'+''.join('<td>'+html.escape(v)+'</td>' for v in cells)+'</tr>')
        body+='<div class="scroll"><table><tr><th>Model</th><th>Conservative call count</th><th>Output allowance</th><th>Quarter / full output scenario</th></tr>'+''.join(rows)+'</table></div>'
        body+=f'<p>Priced-route totals: ${first:.4f} / ${full:.4f} before HTTP retries.</p>'
        body+='<p>Assumes 4,096 input tokens per call; compares one quarter of the configured output allowance with the full allowance. Each route uses the total relevant projected calls, so multi-model totals are deliberately conservative. These are scenarios, not counted input tokens, a spending ceiling or a provider balance.</p>'
        body+='<p>Images, long context, caching, paid transport retries and adaptive attacker-model calls can change the bill. Actual retry policy comes from each configured route. Use the matched-input forecast for counted requests and its funding review.</p>'
        if incomplete:
            body+='<p class="notice amber">Some routes are unpriced; the displayed sum is incomplete. Configure their prices/output allowances before relying on this estimate.</p>'
    except (KeyError,TypeError,ValueError,OSError) as exc:
        body+='<p class="notice amber">Cost estimate unavailable: '+html.escape(str(exc))+'</p>'
    return body+'</section>'
