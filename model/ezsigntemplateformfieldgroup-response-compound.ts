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
import { CustomDropdownElementResponseCompound } from './custom-dropdown-element-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateformfieldResponseCompound } from './ezsigntemplateformfield-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateformfieldgroupResponse } from './ezsigntemplateformfieldgroup-response';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateformfieldgroupResponseCompoundAllOf } from './ezsigntemplateformfieldgroup-response-compound-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateformfieldgroupsignerResponseCompound } from './ezsigntemplateformfieldgroupsigner-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplateformfieldgroupSignerrequirement } from './field-eezsigntemplateformfieldgroup-signerrequirement';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplateformfieldgroupTooltipposition } from './field-eezsigntemplateformfieldgroup-tooltipposition';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplateformfieldgroupType } from './field-eezsigntemplateformfieldgroup-type';

import { DefaultObject } from '../base'

/**
 * @type EzsigntemplateformfieldgroupResponseCompound
 * A Ezsigntemplateformfieldgroup Object and children
 * @export
 */
export type EzsigntemplateformfieldgroupResponseCompound = EzsigntemplateformfieldgroupResponse & EzsigntemplateformfieldgroupResponseCompoundAllOf;


/**
 * @export 
 * A EzsigntemplateformfieldgroupResponseCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigntemplateformfieldgroupResponseCompound
 */
export class DefaultObjectEzsigntemplateformfieldgroupResponseCompound extends DefaultObject {
   pkiEzsigntemplateformfieldgroupID:number = 0
   fkiEzsigntemplatedocumentID:number = 0
   eEzsigntemplateformfieldgroupType:FieldEEzsigntemplateformfieldgroupType = 'Text'
   eEzsigntemplateformfieldgroupSignerrequirement:FieldEEzsigntemplateformfieldgroupSignerrequirement = 'All'
   sEzsigntemplateformfieldgroupLabel:string = ''
   iEzsigntemplateformfieldgroupStep:number = 0
   sEzsigntemplateformfieldgroupDefaultvalue?:string = undefined
   iEzsigntemplateformfieldgroupFilledmin:number = 0
   iEzsigntemplateformfieldgroupFilledmax:number = 0
   bEzsigntemplateformfieldgroupReadonly:boolean = false
   iEzsigntemplateformfieldgroupMaxlength?:number = undefined
   bEzsigntemplateformfieldgroupEncrypted?:boolean = undefined
   sEzsigntemplateformfieldgroupRegexp?:string = undefined
   tEzsigntemplateformfieldgroupTooltip?:string = undefined
   eEzsigntemplateformfieldgroupTooltipposition?:FieldEEzsigntemplateformfieldgroupTooltipposition = undefined
   a_objEzsigntemplateformfieldgroupsigner:Array<EzsigntemplateformfieldgroupsignerResponseCompound> = []
   a_objDropdownElement?:Array<CustomDropdownElementResponseCompound> = undefined
   a_objEzsigntemplateformfield:Array<EzsigntemplateformfieldResponseCompound> = []
}


