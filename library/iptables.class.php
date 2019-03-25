<?php
  namespace Iptables;
  
  require ( 'runcmd.class.php' );
  
  class IptablesException extends \Exception {}
  
  class Iptables {
      
      public $cmd;
      
      const default_iptables_path = '/sbin/iptables',
            ACTION_ACCEPT         = 'ACCEPT',
            ACTION_DROP           = 'DROP',
            ACTION_REJECT         = 'REJECT';
            
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
      * Filter an IP
      * 
      * @param string $ip
      * @return string|false
      */
      public function is_valid_ip( $ip )
      {
         $ip = filter_var( trim( $ip ), FILTER_VALIDATE_IP );
         return empty( $ip ) ? false : $ip;
      } // is_valid_ip
      
      /**
      * Filter a chain
      * 
      * @param string $chain
      * @return string|false
      */
      public function is_valid_chain( $chain )
      {
          $chain = trim( $chain );
          return empty( $chain ) ? false : $chain;
      } // is_valid_chain
      
      /**
      * Filter an action
      * 
      * @param string $action
      * @return string|false
      */
      private function is_valid_action( $action ) 
      {
          $valid_actions = array( self::ACTION_ACCEPT, self::ACTION_DROP, self::ACTION_REJECT );
          $action = strtoupper( trim( $action ) );
          return in_array( $action, $valid_actions ) ? $action : false;
      } // is_valid_action
    
      
      /**
      * Check if the chain exists
      *
      * @param string $chain
      * @return boolean
      */
      public function is_chain( $chain )
      {
          if ( false == ( $chain = $this->is_valid_chain( $chain ) ) ) return false;
          return 0 == $this->cmd->run( '-nL ' . $chain );
      } // is_chain
      
      /**
      * Remove all rules from a chain
      * 
      * @param string $chain
      * @return boolean
      */
      public function flush_chain( $chain )
      {
          if ( false == ( $chain = $this->is_valid_chain( $chain ) ) ) return false;
          return 0 == $this->cmd->run( '-F ' . $chain );
      } // flush_chain
      
      /**
      * Check if the Ip has already been included inside the chain
      *
      * @param string $ip
      * @param string $chain
      * @param string $action
      * @return boolean
      */
      public function is_ip_in_chain( $ip, $chain, $action = self::ACTION_DROP )
      {
         if ( false == ( $ip = $this->is_valid_ip( $ip ) ) ) return false;
         if ( false == ( $chain = $this->is_valid_chain( $chain ) ) ) return false;
         if ( false == ( $action = $this->is_valid_action( $action ) ) ) return false;
         if ( !$this->is_chain( $chain ) ) return false;
         $regex = sprintf('/^%s\s+.*%s/m', $action, str_replace( '.', '\.', $ip ) );
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
         if ( false == ( $chain = $this->is_valid_chain( $chain ) ) ) return false;
         if ( $this->is_chain( $chain ) ) return true;
         return 0 == $this->cmd->run( '-N ' . $chain );
      } // create_chain
      
      /**
      * Append an Ip into a blocking chain
      *
      * @param string $ip
      * @param string $chain
      * @return boolean
      */
      public function block_ip_in_chain( $ip, $chain, $action = self::ACTION_DROP, $comment = '' )
      {
         if ( false == ( $ip = $this->is_valid_ip( $ip ) ) ) return false;
         if ( false == ( $chain = $this->is_valid_chain( $chain ) ) ) return false;
         if ( false == ( $action = $this->is_valid_action( $action ) ) ) return false;
         if ( $this->is_ip_in_chain( $ip, $chain, $action ) ) return true;
         $cmdline = sprintf( '-A %s -s %s -j %s', $chain, $ip, $action );
         $comment = trim( $comment );
         if ( ! empty( $comment ) ) {
             $cmdline .= ' -m comment --comment ' . $comment;
         }
         return 0 == $this->cmd->run( $cmdline );
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
          if ( false == ( $source_chain = $this->is_valid_chain( $source_chain ) ) ) return false;
          if ( false == ( $dest_chain = $this->is_valid_chain( $dest_chain ) ) ) return false;
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
          if ( false == ( $source_chain = $this->is_valid_chain( $source_chain ) ) ) return false;
          if ( false == ( $dest_chain = $this->is_valid_chain( $dest_chain ) ) ) return false;
          if ( $this->is_chain_in_chain( $source_chain, $dest_chain ) ) return true;
          $cmdline = sprintf('-I %s -j %s', $dest_chain, $source_chain );
          return 0 == $this->cmd->run( $cmdline );
      } // add_chain_to_chain
      
      /**
      * Remove an ip from a specific chain
      * 
      * @param string $ip
      * @param string $chain
      * @param string $action
      * @return boolean
      */
      public function remove_ip_from_chain ( $ip, $chain, $action = self::ACTION_DROP )
      {
          if ( false == ( $ip = $this->is_valid_ip( $ip ) ) ) return false;
          if ( false == ( $chain = $this->is_valid_chain( $chain ) ) ) return false;
          if ( false == ( $action = $this->is_valid_action( $action ) ) ) return false;          
          if ( !$this->is_chain( $chain ) ) return false;          
          $regex = '/^' . $action . '\s+.*/m';
          if ( !preg_match_all( $regex, $this->cmd->get_buffer(), $matches ) ) return false;
          $regex = sprintf( '/^%s\s+.*%s/', $action, str_replace( '.', '\.', $ip ) );
          foreach ( $matches[0] as $match ) {              
              if ( 1 == preg_match( $regex, $match ) ) {
                  $cmdline = sprintf( '-D %s -s %s -j %s', $ip, $chain, $action );
                  if ( $this->cmd->run( $cmdline ) != 0 ) return false;
              }
          }
          return true;
      } // remove_ip_from_chain
      
  } // Iptables class    
?>
