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
 * A Discussionmessage Object
 * @export
 * @interface DiscussionmessageRequest
 */
export interface DiscussionmessageRequest {
    /**
     * The unique ID of the Discussionmessage
     * @type {number}
     * @memberof DiscussionmessageRequest
     */
    /*'pkiDiscussionmessageID'?: number;*/
    'pkiDiscussionmessageID'?: number;
    /**
     * The unique ID of the Discussion
     * @type {number}
     * @memberof DiscussionmessageRequest
     */
    /*'fkiDiscussionID': number;*/
    'fkiDiscussionID': number;
    /**
     * The unique ID of the Discussionmembership
     * @type {number}
     * @memberof DiscussionmessageRequest
     */
    /*'fkiDiscussionmembershipIDActionrequired'?: number;*/
    'fkiDiscussionmembershipIDActionrequired'?: number;
    /**
     * The content of the Discussionmessage
     * @type {string}
     * @memberof DiscussionmessageRequest
     */
    /*'tDiscussionmessageContent': string;*/
    'tDiscussionmessageContent': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A DiscussionmessageRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectDiscussionmessageRequest
 */
export class DataObjectDiscussionmessageRequest {
   pkiDiscussionmessageID?:number = undefined
   fkiDiscussionID:number = 0
   fkiDiscussionmembershipIDActionrequired?:number = undefined
   tDiscussionmessageContent:string = ''
}

/**
 * @export 
 * A DiscussionmessageRequest Validation Object
 * @class ValidationObjectDiscussionmessageRequest
 */
export class ValidationObjectDiscussionmessageRequest {
   pkiDiscussionmessageID = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: false
   }
   fkiDiscussionID = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: true
   }
   fkiDiscussionmembershipIDActionrequired = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: false
   }
   tDiscussionmessageContent = {
      type: 'string',
      pattern: '/^.{0,65535}$/',
      required: true
   }
} 


