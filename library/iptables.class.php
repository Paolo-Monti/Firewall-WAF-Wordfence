<?php
  namespace Iptables;
  
  require ( 'runcmd.class.php' );
  
  class IptablesException extends \Exception {}
  
  class Iptables {
      
      public $cmd;
      
      const default_iptables_path = '/sbin/iptables';
      
      /**
      * Constructor
      * 
      * @param string $command_path
      * @return void
      */
      public function __construct( $command_path = self::default_iptables_path )
      {
          $this->cmd = new \RunCmd\RunCmd( $command_path );
      } // Constructor
      
      /**
      * Check if the chain exists
      *
      * @param string $chain
      * @return boolean
      */
      public function is_chain( $chain )
      {
          $chain = trim( $chain );
          return empty( $chain) ? false : 0 == $this->cmd->run( '-nL ' . $chain );
      } // is_chain
      
      /**
      * Check if the Ip has already been included inside the chain
      *
      * @param string $ip
      * @param string $chain
      * @param string $target
      * @return boolean
      */
      public function is_ip_in_chain( $ip, $chain, $target = 'DROP' )
      {
         $ip = filter_var( $ip, FILTER_VALIDATE_IP );
         if ( empty( $ip ) or !$this->is_chain( $chain ) ) return false;
         $regex = sprintf('/^%s\s+.*%s/m', trim( $target ), str_replace( '.', '\.', $ip ) );
         return 1 == preg_match( $regex, $this->cmd->get_buffer() );
      } // is_ip_in_chain
      
      /**
      * Create a chain
      *
      * @param string $chain
      * @return boolean
      */
      public function create_chain( $chain )
      {
         if ( $this->is_chain( $chain ) ) return true;
         $chain = trim( $chain );
         return empty( $chain ) ? false : $this->cmd->run( '-N ' . $chain ) == 0;
      } // create_chain
      
      /**
      * Append an Ip into a blocking chain
      *
      * @param string $ip
      * @param string $chain
      * @return boolean
      */
      public function block_ip_in_chain( $ip, $chain )
      {
         if ( ! ( $ip = filter_var( $ip, FILTER_VALIDATE_IP ) ) ) return false;
         if ( $this->is_ip_in_chain( $ip, $chain ) ) return true;
         $cmdline = sprintf( '-A %s -s %s -j DROP', $chain, $ip );
         return $this->cmd->run( $cmdline ) == 0;
      } // block_ip_in_chain
      
      /**
      * Check if a chain has been already inserted into another chain
      * 
      * @param string $source_chain
      * @param string $dest_chain
      * @param boolean $case_sensitive
      * @return boolean
      */
      public function is_chain_in_chain( $source_chain, $dest_chain, $case_sensitive = true )
      {
          if ( !$this->is_chain( $dest_chain ) ) return false;
          $strpos = $case_sensitive ? 'strpos' : 'stripos';
          return $strpos( $this->cmd->get_buffer(), $source_chain ) !== false;
      } // is_chain_in_chain
      
      /**
      * Add a chain into another chain
      * 
      * @param string $source_chain
      * @param string $dest_chain
      * @param boolean $case_sensitive
      * @return boolean
      */
      public function add_chain_to_chain( $source_chain, $dest_chain, $case_sensitive = true )
      {
          if ( $this->is_chain_in_chain( $source_chain, $dest_chain ) ) return true;
          $cmdline = sprintf('-I %s -j %s', $dest_chain, $source_chain );
          return $this->cmd->run( $cmdline ) == 0;
      } // add_chain_to_chain
      
      /**
      * Remove an ip from a specific chain
      * 
      * @param string $ip
      * @param string $chain
      * @param string $target
      * @return boolean
      */
      public function remove_ip_from_chain ( $ip, $chain, $target = 'DROP' )
      {
          if ( ! ($ip = filter_var( $ip, FILTER_VALIDATE_IP ) ) ) return false;
          $cmdline = sprintf( '-n -L %s', $chain );
          if ( $this->cmd->run( $cmdline) != 0 ) return false;
          $regex = '/^' . $target . '\s+.*/m';
          if ( !preg_match_all( $regex, $this->cmd->get_buffer(), $matches ) ) return false;
          $regex = sprintf( '/^%s\s+.*%s/', trim( $target ), str_replace( '.', '\.', $ip ) );
          foreach ( $matches[0] as $match ) {              
              if ( 1 == preg_match( $regex, $match ) ) {
                  $cmdline = sprintf( '-D -s %s -j %s', $ip, $chain );
                  if ( $this->cmd->run( $cmdline ) != 0 ) return false;
              }
          }
          return true;
      } // remove_ip_from_chain
      
  } // Iptables class    
?>