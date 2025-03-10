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



/**
 * A Discussionmembership Object
 * @export
 * @interface DiscussionmembershipRequest
 */
export interface DiscussionmembershipRequest {
    /**
     * The unique ID of the Discussionmembership
     * @type {number}
     * @memberof DiscussionmembershipRequest
     */
    /*'pkiDiscussionmembershipID'?: number;*/
    'pkiDiscussionmembershipID'?: number;
    /**
     * The unique ID of the Discussion
     * @type {number}
     * @memberof DiscussionmembershipRequest
     */
    /*'fkiDiscussionID': number;*/
    'fkiDiscussionID': number;
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof DiscussionmembershipRequest
     */
    /*'fkiUserID'?: number;*/
    'fkiUserID'?: number;
    /**
     * The unique ID of the Usergroup
     * @type {number}
     * @memberof DiscussionmembershipRequest
     */
    /*'fkiUsergroupID'?: number;*/
    'fkiUsergroupID'?: number;
    /**
     * The unique ID of the Modulesection
     * @type {number}
     * @memberof DiscussionmembershipRequest
     */
    /*'fkiModulesectionID'?: number;*/
    'fkiModulesectionID'?: number;
    /**
     * The joined date of the Discussionmembership
     * @type {string}
     * @memberof DiscussionmembershipRequest
     */
    /*'dtDiscussionmembershipJoined': string;*/
    'dtDiscussionmembershipJoined': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A DiscussionmembershipRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectDiscussionmembershipRequest
 */
export class DataObjectDiscussionmembershipRequest {
   pkiDiscussionmembershipID?:number = undefined
   fkiDiscussionID:number = 0
   fkiUserID?:number = undefined
   fkiUsergroupID?:number = undefined
   fkiModulesectionID?:number = undefined
   dtDiscussionmembershipJoined:string = ''
}

/**
 * @export 
 * A DiscussionmembershipRequest Validation Object
 * @class ValidationObjectDiscussionmembershipRequest
 */
export class ValidationObjectDiscussionmembershipRequest {
   pkiDiscussionmembershipID = {
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
   fkiUserID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiUsergroupID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: false
   }
   fkiModulesectionID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   dtDiscussionmembershipJoined = {
      type: 'string',
      pattern: /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1]) ([01]?[0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])$/,
      required: true
   }
} 


