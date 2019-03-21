<?php
namespace RunCmd;
  
  class RunCmd {
      
      private $command, $fullCmdline, $buffer, $exitCode, $debug;
       
      /**
      * Constructor
      * 
      * @param string $command
      */
      public function __construct( $command )
      {
          $this->command = trim( $command );
          $this->debug = false;
      } // constructor
      
      /**
      * Enable/disable the debug mode
      * 
      * @param boolean $enable
      * @return void
      */
      public function set_debug_mode( $enable )
      {
         $result = filter_var( $enable, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE );
         if ( !is_null( $result ) ) $this->debug = $result;
      } // set_debug_mode
      
      /**
      * Return the captured output of the last command
      * 
      * @return string
      */
      public function get_buffer()
      {
          return $this->buffer;
      } // get_buffer
      
      /**
      * Return the exit code of the last command
      * 
      * @return int
      */
      public function get_exit_code()
      {
          return $this->exitCode;
      } // get_exit_code
      
      /**
      * Get the latest command executed
      * 
      * @return string
      */
      public function get_latest_command()
      {
          return $this->fullCmdline;
      } // get_latest_command
      
      /**
      * Run the command, capturing output and exit code
      * 
      * @param string $cmdline
      * @return exit code
      */
      public function run( $cmdline = '' )
      {
        // Let's reset the internal variables
        $this->buffer = '';
        $this->exitCode = -1;
        
        if ( empty( $this->command ) ) return $this->exitCode;
        
        $command = trim( sprintf("%s %s", $this->command, trim( $cmdline ) ) );
        $this->fullCmdline = $command;
        $command = $command . ' 2>/dev/null';  // Discard messages sent to standard error
        $handle = popen( $command, 'r' );
        while( !feof( $handle ) ) {
            $this->buffer .= fgets( $handle );
        }
        $this->exitCode = pclose( $handle );
        if ( $this->debug ) {
           printf( "Command: %s. Exit code: %d\n", $this->fullCmdline, $this->exitCode );
        }
        return $this->exitCode;
      } // run
  
  } // RunCmd class
?>
