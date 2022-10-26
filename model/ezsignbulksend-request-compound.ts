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
import { EzsignbulksendRequest } from './ezsignbulksend-request';

import { DefaultObject } from '../base'

/**
 * @type EzsignbulksendRequestCompound
 * A Ezsignbulksend Object and children
 * @export
 */
export type EzsignbulksendRequestCompound = EzsignbulksendRequest;


/**
 * @export 
 * A EzsignbulksendRequestCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsignbulksendRequestCompound
 */
export class DefaultObjectEzsignbulksendRequestCompound extends DefaultObject {
   pkiEzsignbulksendID?:number = undefined
   fkiEzsignfoldertypeID:number = 0
   fkiLanguageID:number = 0
   sEzsignbulksendDescription:string = ''
   tEzsignbulksendNote:string = ''
   bEzsignbulksendNeedvalidation:boolean = false
   bEzsignbulksendIsactive:boolean = false
}


