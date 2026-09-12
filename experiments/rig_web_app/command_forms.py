"""Client-side editing of repeated typed command parameters."""

REPEAT_FIELDS_SCRIPT = """
function syncRepeat(group) {
  var rows=Array.from(group.querySelectorAll('.repeat-row'));
  rows.forEach(function(row,index) {
    var field=row.querySelector('input,select,textarea');
    field.name=group.dataset.repeatFlag+(index?'#'+index:'');
    field.setAttribute('aria-label',group.dataset.repeatFlag+' '+(index+1));
    row.querySelector('[data-repeat-remove]').disabled=rows.length===1;
  });
}
function addRepeat(group) {
  var row=group.querySelector('.repeat-row').cloneNode(true);
  var field=row.querySelector('input,select,textarea');
  field.value='';
  group.insertBefore(row,group.querySelector('[data-repeat-add]'));
  syncRepeat(group);
  return field;
}
document.querySelectorAll('[data-repeat-flag]').forEach(function(group) {
  syncRepeat(group);
  group.addEventListener('click',function(event) {
    if(event.target.closest('[data-repeat-add]')) {addRepeat(group).focus();}
    else if(event.target.closest('[data-repeat-remove]')) {
      event.target.closest('.repeat-row').remove();syncRepeat(group);
      group.querySelector('input,select,textarea').focus();
    }
  });
});
function commandField(form,key) {
  var field=Array.from(form.querySelectorAll('[name]')).find(function(item){return item.name===key;});
  if(field) return field;
  var match=/^(--[^#]+)#([1-9][0-9]*)$/.exec(key);
  if(!match) return null;
  var index=Number(match[2]);
  if(!Number.isSafeInteger(index)||index>params.size) return null;
  var group=Array.from(form.querySelectorAll('[data-repeat-flag]')).find(function(item){return item.dataset.repeatFlag===match[1];});
  if(!group) return null;
  while(group.querySelectorAll('.repeat-row').length<=index) addRepeat(group);
  return Array.from(group.querySelectorAll('[name]')).find(function(item){return item.name===key;});
}
"""
