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



/**
 * A Ezsignsignergroupmembership Object
 * @export
 * @interface EzsignsignergroupmembershipRequest
 */
export interface EzsignsignergroupmembershipRequest {
    /**
     * The unique ID of the Ezsignsignergroupmembership
     * @type {number}
     * @memberof EzsignsignergroupmembershipRequest
     */
    'pkiEzsignsignergroupmembershipID'?: number;
    /**
     * The unique ID of the Ezsignsignergroup
     * @type {number}
     * @memberof EzsignsignergroupmembershipRequest
     */
    'fkiEzsignsignergroupID': number;
    /**
     * The unique ID of the Ezsignsigner
     * @type {number}
     * @memberof EzsignsignergroupmembershipRequest
     */
    'fkiEzsignsignerID': number;
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof EzsignsignergroupmembershipRequest
     */
    'fkiUserID': number;
    /**
     * The unique ID of the Usergroup
     * @type {number}
     * @memberof EzsignsignergroupmembershipRequest
     */
    'fkiUsergroupID': number;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignsignergroupmembershipRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignergroupmembershipRequest
 */
export class DataObjectEzsignsignergroupmembershipRequest {
   pkiEzsignsignergroupmembershipID?:number = undefined
   fkiEzsignsignergroupID:number = 0
   fkiEzsignsignerID:number = 0
   fkiUserID:number = 0
   fkiUsergroupID:number = 0
}

/**
 * @export 
 * A EzsignsignergroupmembershipRequest Validation Object
 * @class ValidationObjectEzsignsignergroupmembershipRequest
 */
export class ValidationObjectEzsignsignergroupmembershipRequest {
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


