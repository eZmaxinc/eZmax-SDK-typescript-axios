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
import { MultilingualSubnetDescription } from './multilingual-subnet-description';

/**
 * A Subnet Object
 * @export
 * @interface SubnetRequest
 */
export interface SubnetRequest {
    /**
     * The unique ID of the Subnet
     * @type {number}
     * @memberof SubnetRequest
     */
    'pkiSubnetID'?: number;
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof SubnetRequest
     */
    'fkiUserID'?: number;
    /**
     * The unique ID of the Apikey
     * @type {number}
     * @memberof SubnetRequest
     */
    'fkiApikeyID'?: number;
    /**
     * 
     * @type {MultilingualSubnetDescription}
     * @memberof SubnetRequest
     */
    'objSubnetDescription': MultilingualSubnetDescription;
    /**
     * The network of the Subnet in integer form. For example 8.8.8.0 would be 134744064
     * @type {number}
     * @memberof SubnetRequest
     */
    'iSubnetNetwork': number;
    /**
     * The mask of the Subnet  in integer form. For example 255.255.255.0 would be 4294967040
     * @type {number}
     * @memberof SubnetRequest
     */
    'iSubnetMask': number;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectMultilingualSubnetDescription } from './'
// @ts-ignore
import { ValidationObjectMultilingualSubnetDescription } from './'

/**
 * @export 
 * A SubnetRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectSubnetRequest
 */
export class DataObjectSubnetRequest {
   pkiSubnetID?:number = undefined
   fkiUserID?:number = undefined
   fkiApikeyID?:number = undefined
   objSubnetDescription:MultilingualSubnetDescription = new DataObjectMultilingualSubnetDescription()
   iSubnetNetwork:number = 0
   iSubnetMask:number = 0
}

/**
 * @export 
 * A SubnetRequest Validation Object
 * @class ValidationObjectSubnetRequest
 */
export class ValidationObjectSubnetRequest {
   pkiSubnetID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   fkiUserID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiApikeyID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   objSubnetDescription = new ValidationObjectMultilingualSubnetDescription()
   iSubnetNetwork = {
      type: 'integer',
      minimum: 0,
      maximum: 4294967295,
      required: true
   }
   iSubnetMask = {
      type: 'integer',
      minimum: 0,
      maximum: 4294967295,
      required: true
   }
} 


