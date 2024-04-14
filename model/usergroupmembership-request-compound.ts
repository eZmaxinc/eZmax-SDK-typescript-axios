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
import { UsergroupmembershipRequest } from './usergroupmembership-request';

/**
 * @type UsergroupmembershipRequestCompound
 * A Usergroupmembership Object and children
 * @export
 */
/*export type UsergroupmembershipRequestCompound = UsergroupmembershipRequest;*/
export interface UsergroupmembershipRequestCompound {
    /**
     * The unique ID of the Usergroupmembership
     * @type {number}
     * @memberof UsergroupmembershipRequestCompound
     */
    pkiUsergroupmembershipID?:number 
    /**
     * The unique ID of the Usergroup
     * @type {number}
     * @memberof UsergroupmembershipRequestCompound
     */
    fkiUsergroupID:number 
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof UsergroupmembershipRequestCompound
     */
    fkiUserID?:number 
    /**
     * The unique ID of the Usergroupexternal
     * @type {number}
     * @memberof UsergroupmembershipRequestCompound
     */
    fkiUsergroupexternalID?:number 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UsergroupmembershipRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupmembershipRequestCompound
 */
export class DataObjectUsergroupmembershipRequestCompound {
    pkiUsergroupmembershipID?:number = undefined
    fkiUsergroupID:number = 0
    fkiUserID?:number = undefined
    fkiUsergroupexternalID?:number = undefined
}

/**
 * @export 
 * A UsergroupmembershipRequestCompound Validation Object
 * @class ValidationObjectUsergroupmembershipRequestCompound
 */
export class ValidationObjectUsergroupmembershipRequestCompound {
   pkiUsergroupmembershipID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   fkiUsergroupID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   fkiUserID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiUsergroupexternalID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: false
   }
} 


