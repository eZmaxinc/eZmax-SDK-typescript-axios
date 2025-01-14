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
 * A Discussionmessage Object
 * @export
 * @interface DiscussionmessageRequestPatch
 */
export interface DiscussionmessageRequestPatch {
    /**
     * The unique ID of the Discussionmembership
     * @type {number}
     * @memberof DiscussionmessageRequestPatch
     */
    /*'fkiDiscussionmembershipIDActionrequired'?: number;*/
    'fkiDiscussionmembershipIDActionrequired'?: number;
    /**
     * The content of the Discussionmessage
     * @type {string}
     * @memberof DiscussionmessageRequestPatch
     */
    /*'tDiscussionmessageContent'?: string;*/
    'tDiscussionmessageContent'?: string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A DiscussionmessageRequestPatch Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectDiscussionmessageRequestPatch
 */
export class DataObjectDiscussionmessageRequestPatch {
   fkiDiscussionmembershipIDActionrequired?:number = undefined
   tDiscussionmessageContent?:string = undefined
}

/**
 * @export 
 * A DiscussionmessageRequestPatch Validation Object
 * @class ValidationObjectDiscussionmessageRequestPatch
 */
export class ValidationObjectDiscussionmessageRequestPatch {
   fkiDiscussionmembershipIDActionrequired = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: false
   }
   tDiscussionmessageContent = {
      type: 'string',
      pattern: /^.{0,65535}$/,
      required: false
   }
} 


