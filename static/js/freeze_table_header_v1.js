var Browser = {
  version: function() {
    var version = 999; // we assume a sane browser
    if (navigator.appVersion.indexOf("MSIE") != -1) {
      // bah, IE again, lets downgrade version number
      version = parseFloat(navigator.appVersion.split("MSIE")[1]);
    }

    return version;
  }
};

var table = $('table'),
    thead = table.find('thead'),
    fixed_thead,

    the_window = $(window),

    tr_1, tr_2, did_scroll = false;

thead.find('td').each(function() {
  $(this).css('width', $(this).width());
});

fixed_thead = thead.clone();

thead.after(fixed_thead);

if( Browser.version() < 8 ) {
  fixed_thead.find('tr').css({
    'position': 'absolute',
    'top': 0
  });

  tr_1 = fixed_thead.find('tr:first');
  tr_2 = fixed_thead.find('tr:last').css('margin-top', tr_1.height());
}else {
  fixed_thead.css({
    'position': 'fixed',
    'top': 0,
    'width': table.width()
  });
}

fixed_thead.hide();

the_window.scroll(function() {
  if( the_window.scrollTop() >= table.offset().top ) {
    fixed_thead.show();

    if( Browser.version() < 8 ) {
      did_scroll = true;
    }
  }else {
    fixed_thead.hide();
  }

  if( the_window.scrollTop() > (table.offset().top + table.height()) - fixed_thead.height() ) {
    fixed_thead.hide();
  }
});

setInterval(function() {
  if( did_scroll ) {
    did_scroll = false;
    tr_1.css('top', the_window.scrollTop());
    tr_2.css('top', the_window.scrollTop());
  }
}, 250);