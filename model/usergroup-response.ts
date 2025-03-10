/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { EmailRequest } from './email-request';
// May contain unused imports in some cases
// @ts-ignore
import type { MultilingualUsergroupName } from './multilingual-usergroup-name';

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
    /*'pkiUsergroupID': number;*/
    'pkiUsergroupID': number;
    /**
     * 
     * @type {MultilingualUsergroupName}
     * @memberof UsergroupResponse
     */
    /*'objUsergroupName': MultilingualUsergroupName;*/
    'objUsergroupName': MultilingualUsergroupName;
    /**
     * The Name of the Usergroup in the language of the requester
     * @type {string}
     * @memberof UsergroupResponse
     */
    /*'sUsergroupNameX'?: string;*/
    'sUsergroupNameX'?: string;
    /**
     * 
     * @type {EmailRequest}
     * @memberof UsergroupResponse
     */
    /*'objEmail'?: EmailRequest;*/
    'objEmail'?: EmailRequest;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectMultilingualUsergroupName } from './'
// @ts-ignore
import { DataObjectEmailRequest } from './'
// @ts-ignore
import { ValidationObjectMultilingualUsergroupName } from './'
// @ts-ignore
import { ValidationObjectEmailRequest } from './'

/**
 * @export 
 * A UsergroupResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupResponse
 */
export class DataObjectUsergroupResponse {
   pkiUsergroupID:number = 0
   objUsergroupName:MultilingualUsergroupName = new DataObjectMultilingualUsergroupName()
   sUsergroupNameX?:string = undefined
   objEmail?:EmailRequest = undefined
}

/**
 * @export 
 * A UsergroupResponse Validation Object
 * @class ValidationObjectUsergroupResponse
 */
export class ValidationObjectUsergroupResponse {
   pkiUsergroupID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   objUsergroupName = new ValidationObjectMultilingualUsergroupName()
   sUsergroupNameX = {
      type: 'string',
      pattern: /^.{0,50}$/,
      required: false
   }
   objEmail = new ValidationObjectEmailRequest()
} 


