<?php
  require( 'waf.class.php' );
  
  // Die if no parameter has been supplied on command line 
  // or if the configuration file cannot be read
  !empty( $argv[1] ) and is_readable( $argv[1] ) or die("Please, specify a valid and readable Wordpress configuration file");
  
  define( '_ERROR_LOG_', 'waf.error.log' );
  define( '_5MB_', 5242880 ); // 1024*1024*5 bytes
  
  try {
    $f = new Firewall\WAF( $argv[1] );
    $f->block_all_ip();
  } 
  catch( Exception $e ) {
    // Log the exception inside a file. 
    // If the file size is above 5MB, delete it before to write new content.
    // Loose rotation to prevent a file too big.
    $filename = __DIR__ . DIRECTORY_SEPARATOR . _ERROR_LOG_;
    if ( false != ($info = @stat( $filename ) ) ) {    
       if ( ( $info['size'] / _5MB_ ) > 1 ) {
          unlink( $filename );
       }
    }
    $message = sprintf( "[%s] [%s]\n%s\n", date( 'd-m-Y H:i' ), $e->getMessage(), $e->getTraceAsString() );
    file_put_contents( $filename, $message, FILE_APPEND | LOCK_EX );
  }
?>
