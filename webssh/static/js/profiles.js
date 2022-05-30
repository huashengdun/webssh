(function($){

   $(document).ready(function(){
      $('[data-toggle="tooltip"]').tooltip();

      $('.profile-item').click(function(evt){
         console.log('Selected a profile: '+$(this).text());
         let dd=$(this).parents('div.dropdown:first');
         $(dd).find('button:first').text($(this).text());
         $('input:first').val($(this).attr('value'));

         let profile=$(this).attr('value');
         let found=false;
         for(var i=0; i<profiles.length; i++)
            if(profiles[i]['index']==profile){
               profile=profiles[i];
               found=true;
               break;
            }

         $('form#connect').trigger('reset');
         $('.fld-private-key').show();
         $('.fld-password').show()
         $('input').removeAttr('readonly');
         if(found){
            $('input[name=profile]').val(profile['index']);
            if(profile['host']!=undefined)$('input[name=hostname]').val(profile['host']).attr('readonly', Boolean(profile['host']));
            if(profile['port']!=undefined)$('input[name=port]').val(profile['port']).attr('readonly', Boolean(profile['port']));
            if(profile['username']!=undefined)$('input[name=username]').val(profile['username']).attr('readonly', Boolean(profile['username']));
            if(profile['private-key']){
               $('.fld-private-key').hide();
               $('input[name=passphrase]').focus().select();
               $('.fld-password').hide()
            }else{
               $('input[name=password]').focus().select();
            }
         }

         if(Boolean(Cookies.get('acceptCookies'))){
            console.debug('Store the profile: '+profile['index']+' - '+profile['name']);
            Cookies.set('profileIndex', profile['index']);
            Cookies.set('profileName', profile['name']);
         }

         return this;
      });

      
      let lastIndex=Cookies.get('profileIndex');
      let lastName =Cookies.get('profileName');
      if(Boolean(Cookies.get('acceptCookies')) && lastIndex!=undefined && lastName!=undefined){
         console.debug('Restore the last selected profile: '+lastIndex+' - '+lastName);
         let found=false;
         $('.profile-item').each(function(idx, val){
            if($(this).attr('value')==lastIndex && $(this).text()==lastName){
               found=true;
               $(this).trigger('click');
               console.info('Restored the last profile['+lastIndex+'] - '+lastName);
            }
         });
         if(!found)console.info('Profile index and name mismatched!');
      }

      console.log('/static/js/profiles.js loaded');
   });
})(jQuery);
