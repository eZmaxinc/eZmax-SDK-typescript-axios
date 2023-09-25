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
import { MultilingualUsergroupName } from './multilingual-usergroup-name';
// May contain unused imports in some cases
// @ts-ignore
import { UsergroupResponse } from './usergroup-response';

/**
 * @type UsergroupResponseCompound
 * A Usergroup Object
 * @export
 */
/** export type UsergroupResponseCompound = UsergroupResponse; */
export interface UsergroupResponseCompound {
    /**
     * The unique ID of the Usergroup
     * @type {number}
     * @memberof UsergroupResponseCompound
     */
    pkiUsergroupID:number 
    /**
     * 
     * @type {MultilingualUsergroupName}
     * @memberof UsergroupResponseCompound
     */
    objUsergroupName:MultilingualUsergroupName 
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
 * A UsergroupResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupResponseCompound
 */
export class DataObjectUsergroupResponseCompound {
    pkiUsergroupID:number = 0
    objUsergroupName:MultilingualUsergroupName = new DataObjectMultilingualUsergroupName()
}

/**
 * @export 
 * A UsergroupResponseCompound Validation Object
 * @class ValidationObjectUsergroupResponseCompound
 */
export class ValidationObjectUsergroupResponseCompound {
   pkiUsergroupID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   objUsergroupName = new ValidationObjectMultilingualUsergroupName()
} 


