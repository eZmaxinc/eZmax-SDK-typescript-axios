/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.6
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * The location of the tooltip relative to the Ezsignformfieldgroup\'s location.
 * @export
 * @enum {string}
 */

export const FieldEEzsignformfieldgroupTooltipposition = {
    TopLeft: 'TopLeft',
    TopCenter: 'TopCenter',
    TopRight: 'TopRight',
    MiddleLeft: 'MiddleLeft',
    MiddleCenter: 'MiddleCenter',
    MiddleRight: 'MiddleRight',
    BottomLeft: 'BottomLeft',
    BottomCenter: 'BottomCenter',
    BottomRight: 'BottomRight'
} as const;

export type FieldEEzsignformfieldgroupTooltipposition = typeof FieldEEzsignformfieldgroupTooltipposition[keyof typeof FieldEEzsignformfieldgroupTooltipposition];


