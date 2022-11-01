/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.14
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
import { EzsigntemplateformfieldRequestCompound } from './ezsigntemplateformfield-request-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateformfieldgroupRequest } from './ezsigntemplateformfieldgroup-request';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateformfieldgroupRequestCompoundAllOf } from './ezsigntemplateformfieldgroup-request-compound-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateformfieldgroupsignerRequestCompound } from './ezsigntemplateformfieldgroupsigner-request-compound';
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
 * @type EzsigntemplateformfieldgroupRequestCompound
 * A Ezsigntemplateformfieldgroup Object and children
 * @export
 */
export type EzsigntemplateformfieldgroupRequestCompound = EzsigntemplateformfieldgroupRequest & EzsigntemplateformfieldgroupRequestCompoundAllOf;


/**
 * @export 
 * A EzsigntemplateformfieldgroupRequestCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigntemplateformfieldgroupRequestCompound
 */
export class DefaultObjectEzsigntemplateformfieldgroupRequestCompound extends DefaultObject {
   pkiEzsigntemplateformfieldgroupID?:number = undefined
   fkiEzsigntemplatedocumentID:number = 0
   eEzsigntemplateformfieldgroupType:FieldEEzsigntemplateformfieldgroupType = 'Text'
   eEzsigntemplateformfieldgroupSignerrequirement:FieldEEzsigntemplateformfieldgroupSignerrequirement = 'All'
   sEzsigntemplateformfieldgroupLabel:string = ''
   iEzsigntemplateformfieldgroupStep:number = 0
   sEzsigntemplateformfieldgroupDefaultvalue:string = ''
   iEzsigntemplateformfieldgroupFilledmin:number = 0
   iEzsigntemplateformfieldgroupFilledmax:number = 0
   bEzsigntemplateformfieldgroupReadonly:boolean = false
   iEzsigntemplateformfieldgroupMaxlength?:number = undefined
   bEzsigntemplateformfieldgroupEncrypted?:boolean = undefined
   sEzsigntemplateformfieldgroupRegexp?:string = undefined
   tEzsigntemplateformfieldgroupTooltip?:string = undefined
   eEzsigntemplateformfieldgroupTooltipposition?:FieldEEzsigntemplateformfieldgroupTooltipposition = undefined
   a_objEzsigntemplateformfieldgroupsigner:Array<EzsigntemplateformfieldgroupsignerRequestCompound> = []
   a_objDropdownElement?:Array<CustomDropdownElementRequestCompound> = undefined
   a_objEzsigntemplateformfield:Array<EzsigntemplateformfieldRequestCompound> = []
}


