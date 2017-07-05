var table = $('table'),
    thead = table.find('thead'),
    
    fixed_thead,
    fixed_table = $('<table />', {
      'cellpadding': 5,
      'cellspacing': 0,
      'border': 1,
      'id': 'fixed_table_header'
    }),
    
    fixed_table_wrapper = $('<div />', {
      'height': 400,
      'css': {
        'overflow': 'auto'
      }
    });
    
table.before(fixed_table);

thead.find('td').each(function() {
  $(this).css('width', $(this).width());
});

fixed_thead = thead.clone();
fixed_table.append(fixed_thead);

thead.hide();

table.wrap(fixed_table_wrapper);

// align the new table header with the original table
fixed_table.css('left', (fixed_table.offset().left - table.offset().left) * -1);