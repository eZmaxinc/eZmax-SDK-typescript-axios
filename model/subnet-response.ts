/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
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
 * @interface SubnetResponse
 */
export interface SubnetResponse {
    /**
     * The unique ID of the Subnet
     * @type {number}
     * @memberof SubnetResponse
     */
    /*'pkiSubnetID': number;*/
    'pkiSubnetID': number;
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof SubnetResponse
     */
    /*'fkiUserID'?: number;*/
    'fkiUserID'?: number;
    /**
     * The unique ID of the Apikey
     * @type {number}
     * @memberof SubnetResponse
     */
    /*'fkiApikeyID'?: number;*/
    'fkiApikeyID'?: number;
    /**
     * 
     * @type {MultilingualSubnetDescription}
     * @memberof SubnetResponse
     */
    /*'objSubnetDescription': MultilingualSubnetDescription;*/
    'objSubnetDescription': MultilingualSubnetDescription;
    /**
     * The network of the Subnet in integer form. For example 8.8.8.0 would be 134744064
     * @type {number}
     * @memberof SubnetResponse
     */
    /*'iSubnetNetwork': number;*/
    'iSubnetNetwork': number;
    /**
     * The mask of the Subnet  in integer form. For example 255.255.255.0 would be 4294967040
     * @type {number}
     * @memberof SubnetResponse
     */
    /*'iSubnetMask': number;*/
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
 * A SubnetResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectSubnetResponse
 */
export class DataObjectSubnetResponse {
   pkiSubnetID:number = 0
   fkiUserID?:number = undefined
   fkiApikeyID?:number = undefined
   objSubnetDescription:MultilingualSubnetDescription = new DataObjectMultilingualSubnetDescription()
   iSubnetNetwork:number = 0
   iSubnetMask:number = 0
}

/**
 * @export 
 * A SubnetResponse Validation Object
 * @class ValidationObjectSubnetResponse
 */
export class ValidationObjectSubnetResponse {
   pkiSubnetID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: true
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


