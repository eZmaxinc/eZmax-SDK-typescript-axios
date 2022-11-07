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
import { CustomDropdownElementResponseCompound } from './custom-dropdown-element-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignformfieldResponseCompound } from './ezsignformfield-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignformfieldgroupResponseCompound } from './ezsignformfieldgroup-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignformfieldgroupsignerResponseCompound } from './ezsignformfieldgroupsigner-response-compound';
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
 * @type EzsignformfieldgroupGetObjectV1ResponseMPayload
 * Payload for GET /1/object/ezsignformfieldgroup/{pkiEzsignformfieldgroupID}
 * @export
 */
export type EzsignformfieldgroupGetObjectV1ResponseMPayload = EzsignformfieldgroupResponseCompound;


/**
 * @export 
 * A EzsignformfieldgroupGetObjectV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsignformfieldgroupGetObjectV1ResponseMPayload
 */
export class DefaultObjectEzsignformfieldgroupGetObjectV1ResponseMPayload extends DefaultObject {
   pkiEzsignformfieldgroupID:number = 0
   fkiEzsigndocumentID:number = 0
   eEzsignformfieldgroupType:FieldEEzsignformfieldgroupType = 'Text'
   eEzsignformfieldgroupSignerrequirement:FieldEEzsignformfieldgroupSignerrequirement = 'All'
   sEzsignformfieldgroupLabel:string = ''
   iEzsignformfieldgroupStep:number = 0
   sEzsignformfieldgroupDefaultvalue?:string = undefined
   iEzsignformfieldgroupFilledmin:number = 0
   iEzsignformfieldgroupFilledmax:number = 0
   bEzsignformfieldgroupReadonly:boolean = false
   iEzsignformfieldgroupMaxlength?:number = undefined
   bEzsignformfieldgroupEncrypted?:boolean = undefined
   sEzsignformfieldgroupRegexp?:string = undefined
   tEzsignformfieldgroupTooltip?:string = undefined
   eEzsignformfieldgroupTooltipposition?:FieldEEzsignformfieldgroupTooltipposition = undefined
   a_objEzsignformfield:Array<EzsignformfieldResponseCompound> = []
   a_objDropdownElement?:Array<CustomDropdownElementResponseCompound> = undefined
   a_objEzsignformfieldgroupsigner:Array<EzsignformfieldgroupsignerResponseCompound> = []
}


