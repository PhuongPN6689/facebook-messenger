require 'rack'
require 'json'
require 'openssl'
require 'httparty'

module Facebook
  module Messenger
    class BadRequestError < Error; end

    X_HUB_SIGNATURE_MISSING_WARNING = <<-HEREDOC.freeze
      The X-Hub-Signature header is not present in the request. This is
      expected for the first webhook requests. If it continues after
      some time, check your app's secret token.
    HEREDOC

    #
    # This module holds the server that processes incoming messages from the
    # Facebook Messenger Platform.
    #
    class Server
      def self.call(env)
        new.call(env)
      end

      # Rack handler for request.
      def call(env)
        @request = Rack::Request.new(env)
        @response = Rack::Response.new

        if @request.get?
          verify
        elsif @request.post?
          receive
        else
          @response.status = 405
        end

        @response.finish
      end

      # @private
      private

      #
      # Function validates the verification request which is sent by Facebook
      #   to validate the entered endpoint.
      # @see https://developers.facebook.com/docs/graph-api/webhooks#callback
      #
      def verify
        if valid_verify_token?(@request.params['hub.verify_token'])
          @response.write @request.params['hub.challenge']
        else
          @response.write 'Error; wrong verify token'
        end
      end

      #
      # Function handles the webhook events.
      # @raise BadRequestError if the request is tampered.
      #
      def receive
        check_integrity

        trigger(parsed_body)
      rescue BadRequestError => error
        respond_with_error(error)
      end

      #
      # Check the integrity of the request.
      # @see https://developers.facebook.com/docs/messenger-platform/webhook#security
      #
      # @raise BadRequestError if the request has been tampered with.
      #
      def check_integrity
        # If app secret is not found in environment, return.
        # So for the security purpose always add provision in
        #   configuration provider to return app secret.
        return unless app_secret_for(parsed_body['entry'][0]['id'])

        unless signature.start_with?('sha1='.freeze)
          warn X_HUB_SIGNATURE_MISSING_WARNING

          raise BadRequestError, 'Error getting integrity signature'.freeze
        end

        raise BadRequestError, 'Error checking message integrity'.freeze \
          unless valid_signature?
      end

      # Returns a String describing the X-Hub-Signature header.
      def signature
        @request.env['HTTP_X_HUB_SIGNATURE'.freeze].to_s
      end

      #
      # Verify that the signature given in the X-Hub-Signature header matches
      # that of the body.
      #
      # @return [Boolean] true if request is valid else false.
      #
      def valid_signature?
        Rack::Utils.secure_compare(signature, signature_for(body))
      end

      #
      # Sign the given string.
      #
      # @return [String] A string describing its signature.
      #
      def signature_for(string)
        format('sha1=%<string>s'.freeze, string: generate_hmac(string))
      end

      # Generate a HMAC signature for the given content.
      def generate_hmac(content)
        content_json = JSON.parse(content, symbolize_names: true)
        facebook_page_id = content_json[:entry][0][:id]

        OpenSSL::HMAC.hexdigest('sha1'.freeze,
                                app_secret_for(facebook_page_id),
                                content)
      end

      # Returns a String describing the bot's configured app secret.
      def app_secret_for(facebook_page_id)
        Facebook::Messenger.config.provider.app_secret_for(facebook_page_id)
      end

      # Checks whether a verify token is valid.
      def valid_verify_token?(token)
        Facebook::Messenger.config.provider.valid_verify_token?(token)
      end

      # Returns a String describing the request body.
      def body
        @body ||= @request.body.read
      end

      #
      # Returns a Hash describing the parsed request body.
      # @raise JSON::ParserError if body hash is not valid.
      #
      # @return [JSON] Parsed body hash.
      #
      def parsed_body
        @parsed_body ||= JSON.parse(body)
      rescue JSON::ParserError
        raise BadRequestError, 'Error parsing request body format'
      end

      #
      # Function hand over the webhook event to handlers.
      #
      # @param [Hash] events Parsed body hash in webhook event.
      #
      def trigger(events)
        # Facebook may batch several items in the 'entry' array during
        # periods of high load.
        events['entry'.freeze].each do |entry|
          # If the application has subscribed to webhooks other than Messenger,
          # 'messaging' won't be available and it is not relevant to us.
          puts('{', '"before_json":' + entry.to_s.gsub!('=>', ':') + ',')
          new_entry = change_comment_json(entry)
          puts('"after_json": ' + new_entry.to_s.gsub!('=>', ':'), '}')
          next unless new_entry['messaging'.freeze]

          # Facebook may batch several items in the 'messaging' array during
          # periods of high load.
          new_entry['messaging'.freeze].each do |messaging|
            Facebook::Messenger::Bot.receive(messaging)
          end
        end
      end

      # VSS phuongpn2
      def change_comment_json(json)
        if json.key?('changes')
          new_json = {'id' => json['id'], 'time' => json['time'], 'messaging' => []}
          json['changes'.freeze].each do |item|
            next unless item.key?('field')
            next unless item['field'] == 'feed'

            next unless item.key?('value')
            temp_value = item['value']

            next unless temp_value.key?('item')
            value_item = temp_value['item']

            next unless temp_value.key?('verb')
            value_verb = temp_value['verb']

            next unless temp_value.key?('post_id')
            next unless temp_value.key?('parent_id')
            next unless temp_value.key?('comment_id')

            if temp_value['parent_id'] == temp_value['post_id']
              apical_comment_id = temp_value['comment_id']
            else
              apical_comment_id = temp_value['parent_id']

              # Fix bug binh luan lever 1 vao anh
              temp_channel_facebook_Page = Channel::FacebookPage.find_by(page_id: json['id'])
              if temp_channel_facebook_Page != nil
                begin
                  k = Koala::Facebook::API.new(temp_channel_facebook_Page.page_access_token)
                  result_parent = k.get_object_metadata(temp_value['parent_id']) || {}

                  Rails.logger.info "result_parent['type'] = #{result_parent['type']}"

                  if result_parent['type'] == 'pagepost' || result_parent['type'] == 'post'
                    apical_comment_id = temp_value['comment_id']
                  end
                rescue
                  Rails.logger.info "Error in: k.get_object_metadata(temp_value['parent_id'])"
                end
              end
            end

            @message = Message.find_by(source_id: temp_value['comment_id'])

            new_item = {
              'event' => '',
              'sender' => {'id' => ''},
              'recipient' => {'id' => ''},
              'timestamp' => temp_value['created_time'],
              'root_attributes' => item,
              'message' => {
                'mid' => temp_value['comment_id']
              }
            }
            if temp_value['from']['id'] == json['id']
              new_item['message']['is_echo'] = true
              new_item['sender']['id'] = json['id']
              new_item['recipient']['id'] = apical_comment_id
            else
              new_item['sender']['id'] = apical_comment_id
              new_item['recipient']['id'] = json['id']
            end

            new_item['root_attributes']['apical_comment_id'] = apical_comment_id

            apical_sender_comment = temp_value['from']['id']

            # Lay thong tin tu comment dau tien
            access_token = "access_token=#{Facebook::Messenger.config.provider.access_token_for(json['id'])}"
            response = HTTParty.get("https://graph.facebook.com/v15.0/#{apical_comment_id}?#{access_token}")
            if response.code == 200
              temp_data = JSON.parse response.body
              next if temp_data['from'].nil?
              apical_sender_comment = temp_data['from']['id']
            end

            conversation_comment = apical_sender_comment + '_' + temp_value['post_id'].split(/_/)[1]
            new_item['root_attributes']['apical_sender_comment'] = apical_sender_comment
            new_item['root_attributes']['conversation_comment'] = conversation_comment

            if value_item == 'comment' && value_verb == 'add' && !temp_value.key?('photo')
              access_token = "access_token=#{Facebook::Messenger.config.provider.access_token_for(json['id'])}"
              response = HTTParty.get("https://graph.facebook.com/v15.0/#{temp_value['comment_id']}?fields=message,attachment&#{access_token}")
              if response.code == 200
                temp_data = JSON.parse response.body
                if temp_data['attachment'].present?
                  temp_data = temp_data['attachment']
                  find_photo = false
                  if temp_data['url'].present?
                    find_photo = true
                    temp_value['photo'] = temp_data['url']
                  end
                  if find_photo == true
                    if temp_data['target'].present?
                      if temp_data['target']['url'].present?
                        find_photo = true
                        temp_value['photo'] = temp_data['target']['url']
                      end
                    end
                  end
                  if find_photo == true
                    if temp_data['media'].present?
                      if temp_data['media']['image'].present?
                        if temp_data['media']['image']['src'].present?
                          find_photo = true
                          temp_value['photo'] = temp_data['media']['image']['src']
                        end
                      end
                    end
                  end
                end
              end
            end

            # Su kien them, sua, xoa, an comment
            if value_item == 'comment'

              # Them binh luan
              if value_verb == 'add'
                new_item['event'] = 'add_comment'

                # fix loi lap binh luan
                next unless @message == nil

                # Them noi dung text
                if temp_value.key?('message')
                  new_item['message']['text'] = temp_value['message']
                  add_new_item = true
                end

                # Them noi dung anh
                if temp_value.key?('photo')
                  attachments = [
                    {
                      type: 'image',
                      payload: {
                        url: temp_value['photo']
                      }
                    }
                  ]

                  new_item['message']['attachments'] = attachments
                  add_new_item = true
                end

                if add_new_item
                  new_json['messaging'].append(new_item)
                end
              end

              # Sua binh luan
              if value_verb == 'edited'
                new_item['event'] = 'edited_comment'
                new_json['messaging'].append(new_item)
              end

              # Xoa, an binh luan
              if value_verb == 'remove' || value_verb == 'hide' || value_verb == 'unhide'
                next unless @message != nil
                additional_attributes = @message.additional_attributes

                # Xoa, an binh luan
                case value_verb
                # Xoa binh luan
                when 'remove'
                  new_item['event'] = 'remove_comment'
                  new_json['messaging'].append(new_item)

                # An binh luan
                when 'hide'
                  new_item['event'] = 'hide_comment'
                  new_json['messaging'].append(new_item)

                # Bo an binh luan
                when 'unhide'
                  new_item['event'] = 'unhide_comment'
                  new_json['messaging'].append(new_item)

                end
              end
            end

            # Su kien like
            if value_item == 'reaction'
              next unless @message != nil
              next unless temp_value['from']['id'] == json['id']

              additional_attributes = @message.additional_attributes

              if value_verb == "add" && temp_value['reaction_type'] == "like"
                new_item['event'] = 'like_comment'
                new_json['messaging'].append(new_item)
              else
                new_item['event'] = 'unlike_comment'
                new_json['messaging'].append(new_item)
              end
            end
          end
          if new_json["messaging"].length > 0
            return new_json
          end
        end
        return json
      end

      # def comment_update_message(additional_attributes, content=nil)
      #   if content == nil
      #     @message.update!(additional_attributes: additional_attributes)
      #   else
      #     @message.update!(additional_attributes: additional_attributes, content: content)
      #   end
      # end

      #
      # If received request is tampered, sent 400 code in response.
      #
      # @param [Object] error Error object.
      #
      def respond_with_error(error)
        @response.status = 400
        @response.write(error.message)
        @response.headers['Content-Type'.freeze] = 'text/plain'.freeze
      end
    end
  end
end