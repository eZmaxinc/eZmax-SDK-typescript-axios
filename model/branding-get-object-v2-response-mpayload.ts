/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { BrandingResponseCompound } from './branding-response-compound';

/**
 * Payload for GET /2/object/branding/{pkiBrandingID}
 * @export
 * @interface BrandingGetObjectV2ResponseMPayload
 */
export interface BrandingGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {BrandingResponseCompound}
     * @memberof BrandingGetObjectV2ResponseMPayload
     */
    /*'objBranding': BrandingResponseCompound;*/
    'objBranding': BrandingResponseCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectBrandingResponseCompound } from './'
// @ts-ignore
import { ValidationObjectBrandingResponseCompound } from './'

/**
 * @export 
 * A BrandingGetObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectBrandingGetObjectV2ResponseMPayload
 */
export class DataObjectBrandingGetObjectV2ResponseMPayload {
   objBranding:BrandingResponseCompound = new DataObjectBrandingResponseCompound()
}

/**
 * @export 
 * A BrandingGetObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectBrandingGetObjectV2ResponseMPayload
 */
export class ValidationObjectBrandingGetObjectV2ResponseMPayload {
   objBranding = new ValidationObjectBrandingResponseCompound()
} 


