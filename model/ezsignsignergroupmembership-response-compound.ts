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
import { EzsignsignergroupmembershipResponse } from './ezsignsignergroupmembership-response';

/**
 * @type EzsignsignergroupmembershipResponseCompound
 * A Ezsignsignergroupmembership Object
 * @export
 */
/** export type EzsignsignergroupmembershipResponseCompound = EzsignsignergroupmembershipResponse; */
export interface EzsignsignergroupmembershipResponseCompound {
    /**
     * The unique ID of the Ezsignsignergroupmembership
     * @type {number}
     * @memberof EzsignsignergroupmembershipResponseCompound
     */
    pkiEzsignsignergroupmembershipID:number 
    /**
     * The unique ID of the Ezsignsignergroup
     * @type {number}
     * @memberof EzsignsignergroupmembershipResponseCompound
     */
    fkiEzsignsignergroupID:number 
    /**
     * The unique ID of the Ezsignsigner
     * @type {number}
     * @memberof EzsignsignergroupmembershipResponseCompound
     */
    fkiEzsignsignerID?:number 
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof EzsignsignergroupmembershipResponseCompound
     */
    fkiUserID?:number 
    /**
     * The unique ID of the Usergroup
     * @type {number}
     * @memberof EzsignsignergroupmembershipResponseCompound
     */
    fkiUsergroupID?:number 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignsignergroupmembershipResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignergroupmembershipResponseCompound
 */
export class DataObjectEzsignsignergroupmembershipResponseCompound {
    pkiEzsignsignergroupmembershipID:number = 0
    fkiEzsignsignergroupID:number = 0
    fkiEzsignsignerID?:number = undefined
    fkiUserID?:number = undefined
    fkiUsergroupID?:number = undefined
}

/**
 * @export 
 * A EzsignsignergroupmembershipResponseCompound Validation Object
 * @class ValidationObjectEzsignsignergroupmembershipResponseCompound
 */
export class ValidationObjectEzsignsignergroupmembershipResponseCompound {
   pkiEzsignsignergroupmembershipID = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: true
   }
   fkiEzsignsignergroupID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: true
   }
   fkiEzsignsignerID = {
      type: 'integer',
      minimum: 0,
      required: false
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
} 


