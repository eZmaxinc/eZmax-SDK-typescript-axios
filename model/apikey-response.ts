/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CommonAudit } from './common-audit';
// May contain unused imports in some cases
// @ts-ignore
import { MultilingualApikeyDescription } from './multilingual-apikey-description';

import { DefaultObject } from '../base'

/**
 * An Apikey Object
 * @export
 * @interface ApikeyResponse
 */
export interface ApikeyResponse {
    /**
     * 
     * @type {MultilingualApikeyDescription}
     * @memberof ApikeyResponse
     */
    'objApikeyDescription': MultilingualApikeyDescription;
    /**
     * The secret token for the API key.  This will be returned only on creation.
     * @type {string}
     * @memberof ApikeyResponse
     */
    'sComputedToken'?: string;
    /**
     * The unique ID of the Apikey
     * @type {number}
     * @memberof ApikeyResponse
     */
    'pkiApikeyID': number;
    /**
     * 
     * @type {CommonAudit}
     * @memberof ApikeyResponse
     */
    'objAudit': CommonAudit;
}
/**
 * A ApikeyResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectApikeyResponse
 */
export class DefaultObjectApikeyResponse extends DefaultObject {
   objApikeyDescription:Partial<MultilingualApikeyDescription> = {}
   sComputedToken?:string = undefined
   pkiApikeyID:number = 0
   objAudit:Partial<CommonAudit> = {}
}


