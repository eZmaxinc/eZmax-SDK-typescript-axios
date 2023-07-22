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
import { BrandingRequestCompound } from './branding-request-compound';

/**
 * Request for POST /1/object/branding
 * @export
 * @interface BrandingCreateObjectV1Request
 */
export interface BrandingCreateObjectV1Request {
    /**
     * 
     * @type {Array<BrandingRequestCompound>}
     * @memberof BrandingCreateObjectV1Request
     */
    'a_objBranding': Array<BrandingRequestCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A BrandingCreateObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectBrandingCreateObjectV1Request
 */
export class DataObjectBrandingCreateObjectV1Request {
   a_objBranding:Array<BrandingRequestCompound> = []
}

/**
 * @export 
 * A BrandingCreateObjectV1Request Validation Object
 * @class ValidationObjectBrandingCreateObjectV1Request
 */
export class ValidationObjectBrandingCreateObjectV1Request {
   a_objBranding = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


