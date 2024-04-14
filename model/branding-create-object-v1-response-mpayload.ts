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



/**
 * Payload for POST /1/object/branding
 * @export
 * @interface BrandingCreateObjectV1ResponseMPayload
 */
export interface BrandingCreateObjectV1ResponseMPayload {
    /**
     * An array of unique IDs representing the object that were requested to be created.  They are returned in the same order as the array containing the objects to be created that was sent in the request.
     * @type {Array<number>}
     * @memberof BrandingCreateObjectV1ResponseMPayload
     */
    /*'a_pkiBrandingID': Array<number>;*/
    'a_pkiBrandingID': Array<number>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A BrandingCreateObjectV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectBrandingCreateObjectV1ResponseMPayload
 */
export class DataObjectBrandingCreateObjectV1ResponseMPayload {
   a_pkiBrandingID:Array<number> = []
}

/**
 * @export 
 * A BrandingCreateObjectV1ResponseMPayload Validation Object
 * @class ValidationObjectBrandingCreateObjectV1ResponseMPayload
 */
export class ValidationObjectBrandingCreateObjectV1ResponseMPayload {
   a_pkiBrandingID = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


