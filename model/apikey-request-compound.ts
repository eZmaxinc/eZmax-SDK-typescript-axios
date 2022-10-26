/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.12
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { ApikeyRequest } from './apikey-request';
// May contain unused imports in some cases
// @ts-ignore
import { MultilingualApikeyDescription } from './multilingual-apikey-description';

import { DefaultObject } from '../base'

/**
 * @type ApikeyRequestCompound
 * An Apikey Object and children to create a complete structure
 * @export
 */
export type ApikeyRequestCompound = ApikeyRequest;


/**
 * @export 
 * A ApikeyRequestCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectApikeyRequestCompound
 */
export class DefaultObjectApikeyRequestCompound extends DefaultObject {
   pkiApikeyID?:number = undefined
   fkiUserID:number = 0
   objApikeyDescription:Partial<MultilingualApikeyDescription> = {}
}


