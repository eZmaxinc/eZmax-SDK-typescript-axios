/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.15
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

import { DefaultObject } from '../base'

/**
 * @type ApikeyResponseCompound
 * An Apikey Object and children to create a complete structure
 * @export
 */
export type ApikeyResponseCompound = ApikeyResponse;


/**
 * @export 
 * A ApikeyResponseCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectApikeyResponseCompound
 */
export class DefaultObjectApikeyResponseCompound extends DefaultObject {
   objApikeyDescription:Partial<MultilingualApikeyDescription> = {}
   sComputedToken?:string = undefined
   pkiApikeyID:number = 0
   objAudit:Partial<CommonAudit> = {}
}


