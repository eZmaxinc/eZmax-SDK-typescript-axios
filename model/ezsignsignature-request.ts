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
import { FieldEEzsignsignatureAttachmentnamesource } from './field-eezsignsignature-attachmentnamesource';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignsignatureFont } from './field-eezsignsignature-font';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignsignatureTooltipposition } from './field-eezsignsignature-tooltipposition';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignsignatureType } from './field-eezsignsignature-type';

import { DefaultObject } from '../base'

/**
 * An Ezsignsignature Object
 * @export
 * @interface EzsignsignatureRequest
 */
export interface EzsignsignatureRequest {
    /**
     * The unique ID of the Ezsignsignature
     * @type {number}
     * @memberof EzsignsignatureRequest
     */
    'pkiEzsignsignatureID'?: number;
    /**
     * The unique ID of the Ezsignfoldersignerassociation
     * @type {number}
     * @memberof EzsignsignatureRequest
     */
    'fkiEzsignfoldersignerassociationID': number;
    /**
     * The page number in the Ezsigndocument
     * @type {number}
     * @memberof EzsignsignatureRequest
     */
    'iEzsignpagePagenumber': number;
    /**
     * The X coordinate (Horizontal) where to put the Ezsignsignature on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsignsignature 2 inches from the left border of the page, you would use \"200\" for the X coordinate.
     * @type {number}
     * @memberof EzsignsignatureRequest
     */
    'iEzsignsignatureX': number;
    /**
     * The Y coordinate (Vertical) where to put the Ezsignsignature on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsignsignature 3 inches from the top border of the page, you would use \"300\" for the Y coordinate.
     * @type {number}
     * @memberof EzsignsignatureRequest
     */
    'iEzsignsignatureY': number;
    /**
     * The step when the Ezsignsigner will be invited to sign
     * @type {number}
     * @memberof EzsignsignatureRequest
     */
    'iEzsignsignatureStep': number;
    /**
     * 
     * @type {FieldEEzsignsignatureType}
     * @memberof EzsignsignatureRequest
     */
    'eEzsignsignatureType': FieldEEzsignsignatureType;
    /**
     * The unique ID of the Ezsigndocument
     * @type {number}
     * @memberof EzsignsignatureRequest
     */
    'fkiEzsigndocumentID': number;
    /**
     * A tooltip that will be presented to Ezsignsigner about the Ezsignsignature
     * @type {string}
     * @memberof EzsignsignatureRequest
     */
    'tEzsignsignatureTooltip'?: string;
    /**
     * 
     * @type {FieldEEzsignsignatureTooltipposition}
     * @memberof EzsignsignatureRequest
     */
    'eEzsignsignatureTooltipposition'?: FieldEEzsignsignatureTooltipposition;
    /**
     * 
     * @type {FieldEEzsignsignatureFont}
     * @memberof EzsignsignatureRequest
     */
    'eEzsignsignatureFont'?: FieldEEzsignsignatureFont;
    /**
     * The unique ID of the Ezsignfoldersignerassociation
     * @type {number}
     * @memberof EzsignsignatureRequest
     */
    'fkiEzsignfoldersignerassociationIDValidation'?: number;
    /**
     * Whether the Ezsignsignature is required or not. This field is relevant only with Ezsignsignature with eEzsignsignatureType = Attachments.
     * @type {boolean}
     * @memberof EzsignsignatureRequest
     */
    'bEzsignsignatureRequired'?: boolean;
    /**
     * 
     * @type {FieldEEzsignsignatureAttachmentnamesource}
     * @memberof EzsignsignatureRequest
     */
    'eEzsignsignatureAttachmentnamesource'?: FieldEEzsignsignatureAttachmentnamesource;
    /**
     * The description attached to the attachment name added in Ezsignsignature of eEzsignsignatureType Attachments
     * @type {string}
     * @memberof EzsignsignatureRequest
     */
    'sEzsignsignatureAttachmentdescription'?: string;
    /**
     * The step when the Ezsignsigner will be invited to validate the Ezsignsignature of eEzsignsignatureType Attachments
     * @type {number}
     * @memberof EzsignsignatureRequest
     */
    'iEzsignsignatureValidationstep'?: number;
}
/**
 * A EzsignsignatureRequest Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignsignatureRequest
 */
export class DefaultObjectEzsignsignatureRequest extends DefaultObject {
   pkiEzsignsignatureID?:number = undefined
   fkiEzsignfoldersignerassociationID:number = 0
   iEzsignpagePagenumber:number = 0
   iEzsignsignatureX:number = 0
   iEzsignsignatureY:number = 0
   iEzsignsignatureStep:number = 0
   eEzsignsignatureType:FieldEEzsignsignatureType = 'Acknowledgement'
   fkiEzsigndocumentID:number = 0
   tEzsignsignatureTooltip?:string = undefined
   eEzsignsignatureTooltipposition?:FieldEEzsignsignatureTooltipposition = undefined
   eEzsignsignatureFont?:FieldEEzsignsignatureFont = undefined
   fkiEzsignfoldersignerassociationIDValidation?:number = undefined
   bEzsignsignatureRequired?:boolean = undefined
   eEzsignsignatureAttachmentnamesource?:FieldEEzsignsignatureAttachmentnamesource = undefined
   sEzsignsignatureAttachmentdescription?:string = undefined
   iEzsignsignatureValidationstep?:number = undefined
}


