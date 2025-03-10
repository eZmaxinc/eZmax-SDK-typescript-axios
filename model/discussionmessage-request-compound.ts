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
import type { DiscussionmessageRequest } from './discussionmessage-request';

/**
 * @type DiscussionmessageRequestCompound
 * A Discussionmessage Object and children
 * @export
 */
/*export type DiscussionmessageRequestCompound = DiscussionmessageRequest;*/
export interface DiscussionmessageRequestCompound {
    /**
     * The unique ID of the Discussionmessage
     * @type {number}
     * @memberof DiscussionmessageRequestCompound
     */
    pkiDiscussionmessageID?:number 
    /**
     * The unique ID of the Discussion
     * @type {number}
     * @memberof DiscussionmessageRequestCompound
     */
    fkiDiscussionID:number 
    /**
     * The unique ID of the Discussionmembership
     * @type {number}
     * @memberof DiscussionmessageRequestCompound
     */
    fkiDiscussionmembershipIDActionrequired?:number 
    /**
     * The content of the Discussionmessage
     * @type {string}
     * @memberof DiscussionmessageRequestCompound
     */
    tDiscussionmessageContent:string 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A DiscussionmessageRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectDiscussionmessageRequestCompound
 */
export class DataObjectDiscussionmessageRequestCompound {
    pkiDiscussionmessageID?:number = undefined
    fkiDiscussionID:number = 0
    fkiDiscussionmembershipIDActionrequired?:number = undefined
    tDiscussionmessageContent:string = ''
}

/**
 * @export 
 * A DiscussionmessageRequestCompound Validation Object
 * @class ValidationObjectDiscussionmessageRequestCompound
 */
export class ValidationObjectDiscussionmessageRequestCompound {
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
      pattern: /^.{0,65535}$/,
      required: true
   }
} 


