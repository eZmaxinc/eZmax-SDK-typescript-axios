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
 * A Discussion Object
 * @export
 * @interface DiscussionRequest
 */
export interface DiscussionRequest {
    /**
     * The unique ID of the Discussion
     * @type {number}
     * @memberof DiscussionRequest
     */
    'pkiDiscussionID'?: number;
    /**
     * The description of the Discussion
     * @type {string}
     * @memberof DiscussionRequest
     */
    'sDiscussionDescription': string;
    /**
     * Whether if it\'s an closed
     * @type {boolean}
     * @memberof DiscussionRequest
     */
    'bDiscussionClosed'?: boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A DiscussionRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectDiscussionRequest
 */
export class DataObjectDiscussionRequest {
   pkiDiscussionID?:number = undefined
   sDiscussionDescription:string = ''
   bDiscussionClosed?:boolean = undefined
}

/**
 * @export 
 * A DiscussionRequest Validation Object
 * @class ValidationObjectDiscussionRequest
 */
export class ValidationObjectDiscussionRequest {
   pkiDiscussionID = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: false
   }
   sDiscussionDescription = {
      type: 'string',
      pattern: '/^.{0,75}$/',
      required: true
   }
   bDiscussionClosed = {
      type: 'boolean',
      required: false
   }
} 


