/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { BrandingGetObjectV2ResponseMPayload } from './branding-get-object-v2-response-mpayload';

/**
 * 
 * @export
 * @interface BrandingGetObjectV2ResponseAllOf
 */
export interface BrandingGetObjectV2ResponseAllOf {
    /**
     * 
     * @type {BrandingGetObjectV2ResponseMPayload}
     * @memberof BrandingGetObjectV2ResponseAllOf
     */
    'mPayload': BrandingGetObjectV2ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectBrandingGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectBrandingGetObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A BrandingGetObjectV2ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectBrandingGetObjectV2ResponseAllOf
 */
export class DataObjectBrandingGetObjectV2ResponseAllOf {
   mPayload:BrandingGetObjectV2ResponseMPayload = new DataObjectBrandingGetObjectV2ResponseMPayload()
}

/**
 * @export 
 * A BrandingGetObjectV2ResponseAllOf Validation Object
 * @class ValidationObjectBrandingGetObjectV2ResponseAllOf
 */
export class ValidationObjectBrandingGetObjectV2ResponseAllOf {
   mPayload = new ValidationObjectBrandingGetObjectV2ResponseMPayload()
} 


