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


// May contain unused imports in some cases
// @ts-ignore
import { DiscussionmembershipResponse } from './discussionmembership-response';

/**
 * @type DiscussionmembershipResponseCompound
 * A Discussionmembership Object and children
 * @export
 */
/*export type DiscussionmembershipResponseCompound = DiscussionmembershipResponse;*/
export interface DiscussionmembershipResponseCompound {
    /**
     * The unique ID of the Discussionmembership
     * @type {number}
     * @memberof DiscussionmembershipResponseCompound
     */
    pkiDiscussionmembershipID:number 
    /**
     * The unique ID of the Discussion
     * @type {number}
     * @memberof DiscussionmembershipResponseCompound
     */
    fkiDiscussionID:number 
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof DiscussionmembershipResponseCompound
     */
    fkiUserID?:number 
    /**
     * The unique ID of the Usergroup
     * @type {number}
     * @memberof DiscussionmembershipResponseCompound
     */
    fkiUsergroupID?:number 
    /**
     * The unique ID of the Modulesection
     * @type {number}
     * @memberof DiscussionmembershipResponseCompound
     */
    fkiModulesectionID?:number 
    /**
     * The Description containing the detail of who the Discussionmembership refers to
     * @type {string}
     * @memberof DiscussionmembershipResponseCompound
     */
    sDiscussionmembershipDescription:string 
    /**
     * The joined date of the Discussionmembership
     * @type {string}
     * @memberof DiscussionmembershipResponseCompound
     */
    dtDiscussionmembershipJoined:string 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A DiscussionmembershipResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectDiscussionmembershipResponseCompound
 */
export class DataObjectDiscussionmembershipResponseCompound {
    pkiDiscussionmembershipID:number = 0
    fkiDiscussionID:number = 0
    fkiUserID?:number = undefined
    fkiUsergroupID?:number = undefined
    fkiModulesectionID?:number = undefined
    sDiscussionmembershipDescription:string = ''
    dtDiscussionmembershipJoined:string = ''
}

/**
 * @export 
 * A DiscussionmembershipResponseCompound Validation Object
 * @class ValidationObjectDiscussionmembershipResponseCompound
 */
export class ValidationObjectDiscussionmembershipResponseCompound {
   pkiDiscussionmembershipID = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: true
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
   sDiscussionmembershipDescription = {
      type: 'string',
      pattern: '/^.{0,100}$/',
      required: true
   }
   dtDiscussionmembershipJoined = {
      type: 'string',
      pattern: '/^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1]) ([01]?[0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])$/',
      required: true
   }
} 


