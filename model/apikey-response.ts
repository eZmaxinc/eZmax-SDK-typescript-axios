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
import type { CommonAudit } from './common-audit';
// May contain unused imports in some cases
// @ts-ignore
import type { CustomContactNameResponse } from './custom-contact-name-response';
// May contain unused imports in some cases
// @ts-ignore
import type { MultilingualApikeyDescription } from './multilingual-apikey-description';

/**
 * An Apikey Object
 * @export
 * @interface ApikeyResponse
 */
export interface ApikeyResponse {
    /**
     * The unique ID of the Apikey
     * @type {number}
     * @memberof ApikeyResponse
     */
    /*'pkiApikeyID': number;*/
    'pkiApikeyID': number;
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof ApikeyResponse
     */
    /*'fkiUserID': number;*/
    'fkiUserID': number;
    /**
     * 
     * @type {MultilingualApikeyDescription}
     * @memberof ApikeyResponse
     */
    /*'objApikeyDescription': MultilingualApikeyDescription;*/
    'objApikeyDescription': MultilingualApikeyDescription;
    /**
     * 
     * @type {CustomContactNameResponse}
     * @memberof ApikeyResponse
     */
    /*'objContactName': CustomContactNameResponse;*/
    'objContactName': CustomContactNameResponse;
    /**
     * The Apikey for the API key.  This will be hidden if we are not creating or regenerating the Apikey.
     * @type {string}
     * @memberof ApikeyResponse
     */
    /*'sApikeyApikey'?: string;*/
    'sApikeyApikey'?: string;
    /**
     * The Secret for the API key.  This will be hidden if we are not creating or regenerating the Apikey.
     * @type {string}
     * @memberof ApikeyResponse
     */
    /*'sApikeySecret'?: string;*/
    'sApikeySecret'?: string;
    /**
     * Whether the apikey is active or not
     * @type {boolean}
     * @memberof ApikeyResponse
     */
    /*'bApikeyIsactive': boolean;*/
    'bApikeyIsactive': boolean;
    /**
     * Whether the apikey is signed or not
     * @type {boolean}
     * @memberof ApikeyResponse
     */
    /*'bApikeyIssigned'?: boolean;*/
    'bApikeyIssigned'?: boolean;
    /**
     * 
     * @type {CommonAudit}
     * @memberof ApikeyResponse
     */
    /*'objAudit': CommonAudit;*/
    'objAudit': CommonAudit;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectMultilingualApikeyDescription } from './'
// @ts-ignore
import { DataObjectCustomContactNameResponse } from './'
// @ts-ignore
import { DataObjectCommonAudit } from './'
// @ts-ignore
import { ValidationObjectMultilingualApikeyDescription } from './'
// @ts-ignore
import { ValidationObjectCustomContactNameResponse } from './'
// @ts-ignore
import { ValidationObjectCommonAudit } from './'

/**
 * @export 
 * A ApikeyResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectApikeyResponse
 */
export class DataObjectApikeyResponse {
   pkiApikeyID:number = 0
   fkiUserID:number = 0
   objApikeyDescription:MultilingualApikeyDescription = new DataObjectMultilingualApikeyDescription()
   objContactName:CustomContactNameResponse = new DataObjectCustomContactNameResponse()
   sApikeyApikey?:string = undefined
   sApikeySecret?:string = undefined
   bApikeyIsactive:boolean = false
   bApikeyIssigned?:boolean = undefined
   objAudit:CommonAudit = new DataObjectCommonAudit()
}

/**
 * @export 
 * A ApikeyResponse Validation Object
 * @class ValidationObjectApikeyResponse
 */
export class ValidationObjectApikeyResponse {
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
   objContactName = new ValidationObjectCustomContactNameResponse()
   sApikeyApikey = {
      type: 'string',
      required: false
   }
   sApikeySecret = {
      type: 'string',
      required: false
   }
   bApikeyIsactive = {
      type: 'boolean',
      required: true
   }
   bApikeyIssigned = {
      type: 'boolean',
      required: false
   }
   objAudit = new ValidationObjectCommonAudit()
} 


