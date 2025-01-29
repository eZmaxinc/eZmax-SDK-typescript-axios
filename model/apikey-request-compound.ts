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
import type { ApikeyRequest } from './apikey-request';
// May contain unused imports in some cases
// @ts-ignore
import type { MultilingualApikeyDescription } from './multilingual-apikey-description';

/**
 * @type ApikeyRequestCompound
 * An Apikey Object and children to create a complete structure
 * @export
 */
/*export type ApikeyRequestCompound = ApikeyRequest;*/
export interface ApikeyRequestCompound {
    /**
     * The unique ID of the Apikey
     * @type {number}
     * @memberof ApikeyRequestCompound
     */
    pkiApikeyID?:number 
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof ApikeyRequestCompound
     */
    fkiUserID:number 
    /**
     * 
     * @type {MultilingualApikeyDescription}
     * @memberof ApikeyRequestCompound
     */
    objApikeyDescription:MultilingualApikeyDescription 
    /**
     * Whether the apikey is active or not
     * @type {boolean}
     * @memberof ApikeyRequestCompound
     */
    bApikeyIsactive?:boolean 
    /**
     * Whether the apikey is signed or not
     * @type {boolean}
     * @memberof ApikeyRequestCompound
     */
    bApikeyIssigned?:boolean 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectMultilingualApikeyDescription } from './'
// @ts-ignore
import { ValidationObjectMultilingualApikeyDescription } from './'

/**
 * @export 
 * A ApikeyRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectApikeyRequestCompound
 */
export class DataObjectApikeyRequestCompound {
    pkiApikeyID?:number = undefined
    fkiUserID:number = 0
    objApikeyDescription:MultilingualApikeyDescription = new DataObjectMultilingualApikeyDescription()
    bApikeyIsactive?:boolean = undefined
    bApikeyIssigned?:boolean = undefined
}

/**
 * @export 
 * A ApikeyRequestCompound Validation Object
 * @class ValidationObjectApikeyRequestCompound
 */
export class ValidationObjectApikeyRequestCompound {
   pkiApikeyID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiUserID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   objApikeyDescription = new ValidationObjectMultilingualApikeyDescription()
   bApikeyIsactive = {
      type: 'boolean',
      required: false
   }
   bApikeyIssigned = {
      type: 'boolean',
      required: false
   }
} 


