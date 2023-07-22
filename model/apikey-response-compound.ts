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
import { ApikeyResponse } from './apikey-response';
// May contain unused imports in some cases
// @ts-ignore
import { CommonAudit } from './common-audit';
// May contain unused imports in some cases
// @ts-ignore
import { MultilingualApikeyDescription } from './multilingual-apikey-description';

/**
 * @type ApikeyResponseCompound
 * An Apikey Object and children to create a complete structure
 * @export
 */
export type ApikeyResponseCompound = ApikeyResponse;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectMultilingualApikeyDescription } from './'
// @ts-ignore
import { DataObjectCommonAudit } from './'
// @ts-ignore
import { ValidationObjectMultilingualApikeyDescription } from './'
// @ts-ignore
import { ValidationObjectCommonAudit } from './'

/**
 * @export 
 * A ApikeyResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectApikeyResponseCompound
 */
export class DataObjectApikeyResponseCompound {
    pkiApikeyID:number = 0
    fkiUserID:number = 0
    objApikeyDescription:MultilingualApikeyDescription = new DataObjectMultilingualApikeyDescription()
    sComputedToken?:string = undefined
    bApikeyIsactive:boolean = false
    objAudit:CommonAudit = new DataObjectCommonAudit()
}

/**
 * @export 
 * A ApikeyResponseCompound Validation Object
 * @class ValidationObjectApikeyResponseCompound
 */
export class ValidationObjectApikeyResponseCompound {
   pkiApikeyID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiUserID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   objApikeyDescription = new ValidationObjectMultilingualApikeyDescription()
   sComputedToken = {
      type: 'string',
      required: false
   }
   bApikeyIsactive = {
      type: 'boolean',
      required: true
   }
   objAudit = new ValidationObjectCommonAudit()
} 


