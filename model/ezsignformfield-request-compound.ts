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
import { EzsignformfieldRequest } from './ezsignformfield-request';

import { DefaultObject } from '../base'

/**
 * @type EzsignformfieldRequestCompound
 * An Ezsignformfield Object and children to create a complete structure
 * @export
 */
export type EzsignformfieldRequestCompound = EzsignformfieldRequest;


/**
 * @export 
 * A EzsignformfieldRequestCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsignformfieldRequestCompound
 */
export class DefaultObjectEzsignformfieldRequestCompound extends DefaultObject {
   pkiEzsignformfieldID?:number = undefined
   iEzsignpagePagenumber:number = 0
   sEzsignformfieldLabel:string = ''
   sEzsignformfieldValue?:string = undefined
   iEzsignformfieldX:number = 0
   iEzsignformfieldY:number = 0
   iEzsignformfieldWidth:number = 0
   iEzsignformfieldHeight:number = 0
   bEzsignformfieldSelected?:boolean = undefined
   sEzsignformfieldEnteredvalue?:string = undefined
}


