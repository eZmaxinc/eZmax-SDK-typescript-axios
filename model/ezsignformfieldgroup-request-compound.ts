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
import { CustomDropdownElementRequestCompound } from './custom-dropdown-element-request-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignformfieldRequestCompound } from './ezsignformfield-request-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignformfieldgroupRequest } from './ezsignformfieldgroup-request';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignformfieldgroupRequestCompoundAllOf } from './ezsignformfieldgroup-request-compound-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignformfieldgroupsignerRequestCompound } from './ezsignformfieldgroupsigner-request-compound';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignformfieldgroupSignerrequirement } from './field-eezsignformfieldgroup-signerrequirement';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignformfieldgroupTooltipposition } from './field-eezsignformfieldgroup-tooltipposition';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignformfieldgroupType } from './field-eezsignformfieldgroup-type';

import { DefaultObject } from '../base'

/**
 * @type EzsignformfieldgroupRequestCompound
 * An Ezsignformfieldgroup Object and children to create a complete structure
 * @export
 */
export type EzsignformfieldgroupRequestCompound = EzsignformfieldgroupRequest & EzsignformfieldgroupRequestCompoundAllOf;


/**
 * @export 
 * A EzsignformfieldgroupRequestCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsignformfieldgroupRequestCompound
 */
export class DefaultObjectEzsignformfieldgroupRequestCompound extends DefaultObject {
   pkiEzsignformfieldgroupID?:number = undefined
   fkiEzsigndocumentID:number = 0
   eEzsignformfieldgroupType:FieldEEzsignformfieldgroupType = 'Text'
   eEzsignformfieldgroupSignerrequirement:FieldEEzsignformfieldgroupSignerrequirement = 'All'
   sEzsignformfieldgroupLabel:string = ''
   iEzsignformfieldgroupStep:number = 0
   sEzsignformfieldgroupDefaultvalue:string = ''
   iEzsignformfieldgroupFilledmin:number = 0
   iEzsignformfieldgroupFilledmax:number = 0
   bEzsignformfieldgroupReadonly:boolean = false
   iEzsignformfieldgroupMaxlength?:number = undefined
   bEzsignformfieldgroupEncrypted?:boolean = undefined
   sEzsignformfieldgroupRegexp?:string = undefined
   tEzsignformfieldgroupTooltip?:string = undefined
   eEzsignformfieldgroupTooltipposition?:FieldEEzsignformfieldgroupTooltipposition = undefined
   a_objEzsignformfieldgroupsigner:Array<EzsignformfieldgroupsignerRequestCompound> = []
   a_objDropdownElement?:Array<CustomDropdownElementRequestCompound> = undefined
   a_objEzsignformfield:Array<EzsignformfieldRequestCompound> = []
}


