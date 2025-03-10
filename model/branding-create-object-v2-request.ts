/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { BrandingRequestCompoundV2 } from './branding-request-compound-v2';

/**
 * Request for POST /2/object/branding
 * @export
 * @interface BrandingCreateObjectV2Request
 */
export interface BrandingCreateObjectV2Request {
    /**
     * 
     * @type {Array<BrandingRequestCompoundV2>}
     * @memberof BrandingCreateObjectV2Request
     */
    /*'a_objBranding': Array<BrandingRequestCompoundV2>;*/
    'a_objBranding': Array<BrandingRequestCompoundV2>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A BrandingCreateObjectV2Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectBrandingCreateObjectV2Request
 */
export class DataObjectBrandingCreateObjectV2Request {
   a_objBranding:Array<BrandingRequestCompoundV2> = []
}

/**
 * @export 
 * A BrandingCreateObjectV2Request Validation Object
 * @class ValidationObjectBrandingCreateObjectV2Request
 */
export class ValidationObjectBrandingCreateObjectV2Request {
   a_objBranding = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


