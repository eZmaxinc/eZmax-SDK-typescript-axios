/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignsignergroupmembershipRequest } from './ezsignsignergroupmembership-request';

/**
 * @type EzsignsignergroupmembershipRequestCompound
 * A Ezsignsignergroupmembership Object and children
 * @export
 */
export type EzsignsignergroupmembershipRequestCompound = EzsignsignergroupmembershipRequest;


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignsignergroupmembershipRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignergroupmembershipRequestCompound
 */
export class DataObjectEzsignsignergroupmembershipRequestCompound {
    pkiEzsignsignergroupmembershipID?:number = undefined
    fkiEzsignsignergroupID:number = 0
    fkiEzsignsignerID:number = 0
    fkiUserID:number = 0
    fkiUsergroupID:number = 0
}

/**
 * @export 
 * A EzsignsignergroupmembershipRequestCompound Validation Object
 * @class ValidationObjectEzsignsignergroupmembershipRequestCompound
 */
export class ValidationObjectEzsignsignergroupmembershipRequestCompound {
   pkiEzsignsignergroupmembershipID = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: false
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
      required: true
   }
   fkiUserID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiUsergroupID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
} 


