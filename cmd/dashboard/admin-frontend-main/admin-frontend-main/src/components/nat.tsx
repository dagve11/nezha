import { createNAT, updateNAT } from "@/api/nat"
import { Button } from "@/components/ui/button"
import {
    Dialog,
    DialogClose,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
} from "@/components/ui/dialog"
import {
    Form,
    FormControl,
    FormDescription,
    FormField,
    FormItem,
    FormLabel,
    FormMessage,
} from "@/components/ui/form"
import { Input } from "@/components/ui/input"
import { ScrollArea } from "@/components/ui/scroll-area"
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select"
import { IconButton } from "@/components/xui/icon-button"
import { useServer } from "@/hooks/useServer"
import { ModelNAT, ModelNATForm, ServerIdentifierType } from "@/types"
import { zodResolver } from "@hookform/resolvers/zod"
import { useState } from "react"
import { useForm } from "react-hook-form"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"
import { KeyedMutator } from "swr"
import { z } from "zod"

import { Checkbox } from "./ui/checkbox"
import { Label } from "./ui/label"

interface NATCardProps {
    data?: ModelNAT
    mutate: KeyedMutator<ModelNAT[]>
}

export const NAT_LOCAL_HOST = "127.0.0.1"

export function extractNATLocalPort(host?: string): number {
    const match = host?.trim().match(/:(\d+)$/)
    const port = Number(match?.[1])
    return Number.isInteger(port) && port > 0 && port <= 65535 ? port : 0
}

export function natServerLabel(
    servers: ServerIdentifierType[] | undefined,
    serverID: number,
    fallbackName?: string,
) {
    const server = servers?.find((item) => item.id === serverID)
    const name = server?.name || fallbackName || `#${serverID}`
    return `${name} (#${serverID})`
}

const natFormSchema = z.object({
    enabled: z.boolean(),
    server_id: z.coerce.number().int().min(1),
    local_port: z.coerce.number().int().min(1).max(65535),
    port: z.coerce.number().int().min(1).max(65535),
})

type NatFormInput = z.input<typeof natFormSchema>
type NatFormData = z.output<typeof natFormSchema>

export const NATCard: React.FC<NATCardProps> = ({ data, mutate }) => {
    const { t } = useTranslation()
    const { servers = [] } = useServer()
    const form = useForm<NatFormInput, unknown, NatFormData>({
        resolver: zodResolver(natFormSchema),
        defaultValues: data
            ? {
                  enabled: data.enabled ?? false,
                  server_id: data.server_id ?? 0,
                  local_port: extractNATLocalPort(data.host),
                  port: data.port ?? 0,
              }
            : {
                  enabled: false,
                  server_id: 0,
                  local_port: 0,
                  port: 0,
              },
        resetOptions: {
            keepDefaultValues: false,
        },
    })

    const [open, setOpen] = useState(false)

    const onSubmit = async (values: NatFormData) => {
        try {
            const selectedServer = servers.find((server) => server.id === values.server_id)
            const payload: ModelNATForm = {
                name: selectedServer?.name || data?.name || `#${values.server_id}`,
                enabled: values.enabled,
                server_id: values.server_id,
                local_port: values.local_port,
                host: `${NAT_LOCAL_HOST}:${values.local_port}`,
                port: values.port,
            }
            if (data?.id) {
                await updateNAT(data.id, payload)
            } else {
                await createNAT(payload)
            }
        } catch (e) {
            console.error(e)
            const description =
                e instanceof Error && e.message ? e.message : t("Results.UnExpectedError")
            toast(t("Error"), {
                description,
            })
            return
        }
        setOpen(false)
        await mutate()
        form.reset()
    }

    return (
        <Dialog open={open} onOpenChange={setOpen}>
            <DialogTrigger asChild>
                {data ? <IconButton variant="outline" icon="edit" /> : <IconButton icon="plus" />}
            </DialogTrigger>
            <DialogContent className="sm:max-w-xl">
                <ScrollArea className="max-h-[calc(100dvh-5rem)] p-3">
                    <div className="items-center mx-1">
                        <DialogHeader>
                            <DialogTitle>{data ? t("EditNAT") : t("CreateNAT")}</DialogTitle>
                            <DialogDescription>{t("NATDialogHint")}</DialogDescription>
                        </DialogHeader>
                        <Form {...form}>
                            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-2 my-2">
                                <FormField
                                    control={form.control}
                                    name="server_id"
                                    render={({ field }) => (
                                        <FormItem>
                                            <FormLabel>{t("NATTargetMachine")}</FormLabel>
                                            <FormControl>
                                                <Select
                                                    value={String(field.value ?? 0)}
                                                    onValueChange={(value) =>
                                                        field.onChange(Number(value))
                                                    }
                                                >
                                                    <SelectTrigger>
                                                        <SelectValue
                                                            placeholder={t("SelectServer")}
                                                        />
                                                    </SelectTrigger>
                                                    <SelectContent>
                                                        <SelectItem value="0" disabled>
                                                            {t("SelectServer")}
                                                        </SelectItem>
                                                        {servers.map((server) => (
                                                            <SelectItem
                                                                key={server.id}
                                                                value={String(server.id)}
                                                            >
                                                                {natServerLabel(
                                                                    servers,
                                                                    server.id,
                                                                    server.name,
                                                                )}
                                                            </SelectItem>
                                                        ))}
                                                    </SelectContent>
                                                </Select>
                                            </FormControl>
                                            <FormDescription>
                                                {t("NATTargetMachineHint")}
                                            </FormDescription>
                                            <FormMessage />
                                        </FormItem>
                                    )}
                                />
                                <FormField
                                    control={form.control}
                                    name="local_port"
                                    render={({ field }) => {
                                        const { value, ...fieldProps } = field
                                        return (
                                            <FormItem>
                                                <FormLabel>{t("LocalPort")}</FormLabel>
                                                <FormControl>
                                                    <div className="flex">
                                                        <span className="inline-flex h-10 items-center rounded-l-md border border-r-0 border-input bg-muted px-3 text-sm text-muted-foreground">
                                                            {NAT_LOCAL_HOST}:
                                                        </span>
                                                        <Input
                                                            className="rounded-l-none"
                                                            type="number"
                                                            min={1}
                                                            max={65535}
                                                            placeholder="8000"
                                                            value={String(value ?? "")}
                                                            {...fieldProps}
                                                        />
                                                    </div>
                                                </FormControl>
                                                <FormDescription>
                                                    {t("NATLocalPortHint")}
                                                </FormDescription>
                                                <FormMessage />
                                            </FormItem>
                                        )
                                    }}
                                />
                                <FormField
                                    control={form.control}
                                    name="port"
                                    render={({ field }) => {
                                        const { value, ...fieldProps } = field
                                        return (
                                            <FormItem>
                                                <FormLabel>{t("BindPort")}</FormLabel>
                                                <FormControl>
                                                    <Input
                                                        type="number"
                                                        min={1}
                                                        max={65535}
                                                        placeholder="2222"
                                                        value={String(value ?? "")}
                                                        {...fieldProps}
                                                    />
                                                </FormControl>
                                                <FormDescription>
                                                    {t("NATBindPortHint")}
                                                </FormDescription>
                                                <FormMessage />
                                            </FormItem>
                                        )
                                    }}
                                />
                                <FormField
                                    control={form.control}
                                    name="enabled"
                                    render={({ field }) => (
                                        <FormItem className="flex items-center space-x-2">
                                            <FormControl>
                                                <div className="flex items-center gap-2">
                                                    <Checkbox
                                                        checked={field.value === true}
                                                        onCheckedChange={field.onChange}
                                                    />
                                                    <Label className="text-sm">{t("Enable")}</Label>
                                                </div>
                                            </FormControl>
                                            <FormMessage />
                                        </FormItem>
                                    )}
                                />
                                <DialogFooter className="justify-end">
                                    <DialogClose asChild>
                                        <Button type="button" className="my-2" variant="secondary">
                                            {t("Close")}
                                        </Button>
                                    </DialogClose>
                                    <Button type="submit" className="my-2">
                                        {t("Confirm")}
                                    </Button>
                                </DialogFooter>
                            </form>
                        </Form>
                    </div>
                </ScrollArea>
            </DialogContent>
        </Dialog>
    )
}
