Rails.application.routes.draw do
  get '/login', to: 'sessions#new', as: :new_session
  post '/login', to: 'sessions#create', as: :create_session
  delete '/logout', to: 'sessions#destroy', as: :destroy_session

  get '/reset-password', to: 'passwords#new', as: :reset_password
  post '/reset-password', to: 'passwords#create'
  get '/reset-password/edit', to: 'passwords#edit', as: :edit_password, param: :token
  patch '/reset-password', to: 'passwords#update', param: :token

  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html

  # Reveal health status on /up that returns 200 if the app boots with no exceptions, otherwise 500.
  # Can be used by load balancers and uptime monitors to verify that the app is live.
  get 'up' => 'rails/health#show', :as => :rails_health_check

  # Render dynamic PWA files from app/views/pwa/* (remember to link manifest in application.html.erb)
  # get "manifest" => "rails/pwa#manifest", as: :pwa_manifest
  # get "service-worker" => "rails/pwa#service_worker", as: :pwa_service_worker

  # Defines the root path route ("/")
  # root "posts#index"
end
