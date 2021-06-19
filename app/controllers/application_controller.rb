class ApplicationController < ActionController::API
  def secret_key
    "secret"
  end

  #given a payload {user_id: ?} => token
  def encode(payload)
    JWT.encode(payload, secret_key, 'HS256')
  end

  def decode(token)
    JWT.decode(token, "secret", true, {algorithm: "HS256"})[0]
  end

  def login
    user = User.find_by(email: params[:email])

    if user && user.authenticate(params[:password])
      payload = {user_id: user.id}
      token = encode(payload)
      render :json => {user: user, token: token}
    else
      render json: {error: "User not found"}
    end

  def token_authenticate

    token = request.headers["Authenticate"]
    user = User.find(decode(token)["user_id"])

    render json: user
  end
end
