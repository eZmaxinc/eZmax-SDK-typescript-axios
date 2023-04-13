/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { MultilingualUsergroupName } from './multilingual-usergroup-name';

/**
 * A Usergroup Object
 * @export
 * @interface UsergroupResponse
 */
export interface UsergroupResponse {
    /**
     * The unique ID of the Usergroup
     * @type {number}
     * @memberof UsergroupResponse
     */
    'pkiUsergroupID': number;
    /**
     * 
     * @type {MultilingualUsergroupName}
     * @memberof UsergroupResponse
     */
    'objUsergroupName': MultilingualUsergroupName;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectMultilingualUsergroupName } from './'
// @ts-ignore
import { ValidationObjectMultilingualUsergroupName } from './'

/**
 * @export 
 * A UsergroupResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupResponse
 */
export class DataObjectUsergroupResponse {
   pkiUsergroupID:number = 0
   objUsergroupName:MultilingualUsergroupName = new DataObjectMultilingualUsergroupName()
}

/**
 * @export 
 * A UsergroupResponse Validation Object
 * @class ValidationObjectUsergroupResponse
 */
export class ValidationObjectUsergroupResponse {
   pkiUsergroupID = {
      type: 'integer',
      minimum: 1,
      maximum: 255,
      required: true
   }
   objUsergroupName = new ValidationObjectMultilingualUsergroupName()
} 


