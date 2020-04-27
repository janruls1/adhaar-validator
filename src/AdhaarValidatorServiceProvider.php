<?php

namespace janruls1\AdhaarValidator;

use Illuminate\Support\Facades\Validator;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\File;

class AdhaarValidatorServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap the application services.
     *
     * @return void
     */
    public function boot()
    {
        $this->publishes([
            __DIR__.'/config/adhaar-validator.php' => config_path('adhaar-validator.php'),
        ]);

        $this->mergeConfigFrom(
            __DIR__.'/config/adhaar-validator.php', 'adhaar-validator'
        );
        
        Validator::extend('valid_aadhaar_xml_file', function($attribute, $value){
            return app('aadhaarValidator')::_validateAdhaarXml(File::get($value->getRealPath()));
        });

        Validator::extend('valid_aadhaar_no', function($attribute, $value){
            return app('aadhaarValidator')::_validateAdhaarNo($value);
        });

        Validator::extend('valid_aadhaar_xml', function($attribute, $value){
            return app('aadhaarValidator')::_validateAdhaarXml($value);
        });
    }

    /**
     * Register the application services.
     *
     * @return void
     */
    public function register()
    {
        $this->app->singleton('aadhaarValidator', static function ($app) {
            return $app->make(AdhaarValidator::class);
        });
    }
}
