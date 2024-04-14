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
import { UsergroupdelegationRequest } from './usergroupdelegation-request';

/**
 * @type UsergroupdelegationRequestCompound
 * A Usergroupdelegation Object and children
 * @export
 */
/*export type UsergroupdelegationRequestCompound = UsergroupdelegationRequest;*/
export interface UsergroupdelegationRequestCompound {
    /**
     * The unique ID of the Usergroupdelegation
     * @type {number}
     * @memberof UsergroupdelegationRequestCompound
     */
    pkiUsergroupdelegationID?:number 
    /**
     * The unique ID of the Usergroup
     * @type {number}
     * @memberof UsergroupdelegationRequestCompound
     */
    fkiUsergroupID:number 
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof UsergroupdelegationRequestCompound
     */
    fkiUserID:number 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UsergroupdelegationRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupdelegationRequestCompound
 */
export class DataObjectUsergroupdelegationRequestCompound {
    pkiUsergroupdelegationID?:number = undefined
    fkiUsergroupID:number = 0
    fkiUserID:number = 0
}

/**
 * @export 
 * A UsergroupdelegationRequestCompound Validation Object
 * @class ValidationObjectUsergroupdelegationRequestCompound
 */
export class ValidationObjectUsergroupdelegationRequestCompound {
   pkiUsergroupdelegationID = {
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
      required: true
   }
} 


