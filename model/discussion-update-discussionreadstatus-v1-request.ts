/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * Request for POST /1/object/discussion/{pkiDiscussionID}/updateDiscussionreadstatus
 * @export
 * @interface DiscussionUpdateDiscussionreadstatusV1Request
 */
export interface DiscussionUpdateDiscussionreadstatusV1Request {
    /**
     * The date of the last discussion message read
     * @type {string}
     * @memberof DiscussionUpdateDiscussionreadstatusV1Request
     */
    /*'dtDiscussionreadstatusDate'?: string;*/
    'dtDiscussionreadstatusDate'?: string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A DiscussionUpdateDiscussionreadstatusV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectDiscussionUpdateDiscussionreadstatusV1Request
 */
export class DataObjectDiscussionUpdateDiscussionreadstatusV1Request {
   dtDiscussionreadstatusDate?:string = undefined
}

/**
 * @export 
 * A DiscussionUpdateDiscussionreadstatusV1Request Validation Object
 * @class ValidationObjectDiscussionUpdateDiscussionreadstatusV1Request
 */
export class ValidationObjectDiscussionUpdateDiscussionreadstatusV1Request {
   dtDiscussionreadstatusDate = {
      type: 'string',
      pattern: '/^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1]) ([01]?[0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])$/',
      required: false
   }
} 

