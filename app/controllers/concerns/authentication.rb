module Authentication
  extend ActiveSupport::Concern

  included do
    before_action :require_authentication
    helper_method :authenticated?
  end

  class_methods do
    def allow_unauthenticated_access(**options)
      skip_before_action :require_authentication, **options
    end
  end

  private

  # checks if a current session exists
  def authenticated?
    resume_session
  end

  # Checks if a session exists otherwise we request authentication
  def require_authentication
    resume_session || request_authentication
  end

  # Check if Current.session exists
  # otherwise if Current.session does not exist we try to find a session from our cookies
  # if session is found from our cookies we set Current.session to the session found
  # otherwise we return nil
  def resume_session
    Current.session ||= find_session_by_cookie
  end

  # If signed :session_id cookie exists query the session table for a record with a matching id
  # otherwise the method returns nil
  def find_session_by_cookie
    Session.find_by(id: cookies.signed[:session_id]) if cookies.signed[:session_id]
  end

  # If request.url requires authentication & user is not signed in,
  # save request.url in session[:return_to_after_authenticating] and redirect to log in page.
  def request_authentication
    session[:return_to_after_authenticating] = request.url
    redirect_to new_session_path
  end

  # If session[:return_to_after_authenticating] exists redirect user to url
  # otherwise redirect to root_url
  def after_authentication_url
    session.delete(:return_to_after_authenticating) || root_url
  end

  # Creates a new session record associated with the given user, storing the user agent and IP address.
  # After creation, sets Current.session to the new session and stores the session ID
  # in a signed, permanent cookie that is HTTP-only and uses SameSite=Lax for CSRF protection.
  def start_new_session_for(user)
    user
      .sessions
      .create!(user_agent: request.user_agent, ip_address: request.remote_ip)
      .tap do |session|
        Current.session = session
        cookies.signed.permanent[:session_id] = { value: session.id, httponly: true, same_site: :lax }
      end
  end

  # Destroys the current session record in the database,
  # removes the :session_id cookie, and clears Current.session
  # and clears Current.session from memory
  def terminate_session
    Current.session.destroy
    cookies.delete(:session_id)
    Current.session = nil
  end
end
