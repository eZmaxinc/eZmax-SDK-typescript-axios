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
 * A Ezsignsignergroupmembership Object
 * @export
 * @interface EzsignsignergroupmembershipResponse
 */
export interface EzsignsignergroupmembershipResponse {
    /**
     * The unique ID of the Ezsignsignergroupmembership
     * @type {number}
     * @memberof EzsignsignergroupmembershipResponse
     */
    /*'pkiEzsignsignergroupmembershipID': number;*/
    'pkiEzsignsignergroupmembershipID': number;
    /**
     * The unique ID of the Ezsignsignergroup
     * @type {number}
     * @memberof EzsignsignergroupmembershipResponse
     */
    /*'fkiEzsignsignergroupID': number;*/
    'fkiEzsignsignergroupID': number;
    /**
     * The unique ID of the Ezsignsigner
     * @type {number}
     * @memberof EzsignsignergroupmembershipResponse
     */
    /*'fkiEzsignsignerID'?: number;*/
    'fkiEzsignsignerID'?: number;
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof EzsignsignergroupmembershipResponse
     */
    /*'fkiUserID'?: number;*/
    'fkiUserID'?: number;
    /**
     * The unique ID of the Usergroup
     * @type {number}
     * @memberof EzsignsignergroupmembershipResponse
     */
    /*'fkiUsergroupID'?: number;*/
    'fkiUsergroupID'?: number;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignsignergroupmembershipResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignergroupmembershipResponse
 */
export class DataObjectEzsignsignergroupmembershipResponse {
   pkiEzsignsignergroupmembershipID:number = 0
   fkiEzsignsignergroupID:number = 0
   fkiEzsignsignerID?:number = undefined
   fkiUserID?:number = undefined
   fkiUsergroupID?:number = undefined
}

/**
 * @export 
 * A EzsignsignergroupmembershipResponse Validation Object
 * @class ValidationObjectEzsignsignergroupmembershipResponse
 */
export class ValidationObjectEzsignsignergroupmembershipResponse {
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


